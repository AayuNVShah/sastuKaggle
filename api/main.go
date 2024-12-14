package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/sha3"
)

// -------------------------------- DB Connections and Functions --------------------------------
var mongoClient *mongo.Client

func InitDB() {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI("mongodb+srv://dhairyas4:PJgCjCjuFsD80A6H@cluster0.bcucc.mongodb.net/Compiler?retryWrites=true&w=majority&appName=Cluster0").SetServerAPIOptions(serverAPI)

	var err error
	mongoClient, err = mongo.Connect(context.TODO(), opts)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	if err := mongoClient.Database("admin").RunCommand(context.TODO(), primitive.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}
	log.Println("Connected to MongoDB!")
}

func CloseDB() {
	if err := mongoClient.Disconnect(context.TODO()); err != nil {
		log.Fatalf("Failed to disconnect from MongoDB: %v", err)
	}
}

// -------------------------------- Core API Payloads & Handlers --------------------------------

type NewCodePayload struct {
	FileName string `json:"file_name"`
	Code     string `json:"code"`
}

func NewCodeHandler(w http.ResponseWriter, r *http.Request) {
	var payload NewCodePayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	database := mongoClient.Database("gokaggle")
	snippetsCollection := database.Collection("compiler")

	insertResult, err := snippetsCollection.InsertOne(context.TODO(), payload)
	if err != nil {
		http.Error(w, "Failed to save snippet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Code saved successfully, ID: %v", insertResult.InsertedID)
}

type ExecutePayload struct {
	Code string `json:"code"`
}

func ExecuteHandler(w http.ResponseWriter, r *http.Request) {
	var payload ExecutePayload

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Received execution request from %s at %d.\nCode:\n%s\n", "test_user", 25000000, payload.Code)

	output, err := runCodeInContainer(payload.Code)
	if err != nil {
		log.Printf("Error running code in container: %s", err)
		http.Error(w, "Failed to execute code", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"status":  "success",
		"message": "Execution received",
		"output":  output,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func runCodeInContainer(code string) (string, error) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", err
	}
	cli.NegotiateAPIVersion(ctx)

	image := "golang:1.20-alpine"

	_, err = cli.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		return "", err
	}

	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:      image,
			WorkingDir: "/app",
			Cmd:        []string{"sh", "-c", "while true; do sleep 1; done"},
			Tty:        true,
		},
		&container.HostConfig{},
		nil, nil, "",
	)
	if err != nil {
		return "", err
	}
	containerID := resp.ID

	if err := copyCodeToContainer(cli, ctx, containerID, code, "main.go"); err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}

	if err := cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}

	execResp, err := cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          []string{"go", "run", "main.go"},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}

	attachResp, err := cli.ContainerExecAttach(ctx, execResp.ID, types.ExecStartCheck{})
	if err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}
	defer attachResp.Close()

	var stdoutBuf bytes.Buffer
	_, err = io.Copy(&stdoutBuf, attachResp.Reader)
	if err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}

	inspectResp, err := cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		cleanupContainer(cli, ctx, containerID)
		return "", err
	}

	cleanupContainer(cli, ctx, containerID)

	cleanedOutput := sanitizeOutput(stdoutBuf.String())

	if inspectResp.ExitCode != 0 {
		return cleanedOutput, nil
	}

	return cleanedOutput, nil
}

func sanitizeOutput(output string) string {
	var result bytes.Buffer
	for _, char := range output {
		if char >= 32 && char <= 126 || char == '\n' || char == '\r' {
			result.WriteRune(char)
		}
	}
	return result.String()
}

func copyCodeToContainer(cli *client.Client, ctx context.Context, containerID, code, filename string) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	data := []byte(code)
	hdr := &tar.Header{
		Name: filename,
		Mode: 0644,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		tw.Close()
		return err
	}

	if _, err := tw.Write(data); err != nil {
		tw.Close()
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}

	return cli.CopyToContainer(ctx, containerID, "/app", &buf, types.CopyToContainerOptions{})
}

func cleanupContainer(cli *client.Client, ctx context.Context, containerID string) {
	cli.ContainerStop(ctx, containerID, container.StopOptions{})
	cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force: true,
	})
}

// -------------------------------- Authentication API Payloads & Handlers --------------------------------

func hashPassword(password string) string {
	hasher := sha3.New256()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

func verifyPassword(hashedPassword, plainPassword string) bool {
	return hashedPassword == hashPassword(plainPassword)
}

type UserPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var payload UserPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	payload.Password = hashPassword(payload.Password)

	database := mongoClient.Database("gokaggle")
	snippetsCollection := database.Collection("users")

	insertResult, err := snippetsCollection.InsertOne(context.TODO(), payload)
	if err != nil {
		http.Error(w, "Failed to save snippet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Code saved successfully, ID: %v", insertResult.InsertedID)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var payload UserPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	database := mongoClient.Database("gokaggle")
	usersCollection := database.Collection("users")

	var user UserPayload
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": payload.Email}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Failed to fetch user", http.StatusInternalServerError)
		return
	}

	if !verifyPassword(user.Password, payload.Password) {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Login successful")
}

func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Hello World!")
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", HelloWorldHandler)
	r.Post("/register", RegisterHandler)
	r.Post("/login", LoginHandler)
	r.Post("/execute", ExecuteHandler)

	http.ListenAndServe(":3333", r)
	fmt.Println("Server is running on port 3333")
}
