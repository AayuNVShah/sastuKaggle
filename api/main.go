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
	"sync"

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
var dockerClient *client.Client
var userContainers sync.Map

func InitDB() {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI("mongodb+srv://vraj:jRXl9CWhcmqja6Lm@sastukaggle.2kw7w.mongodb.net/?retryWrites=true&w=majority&appName=sastuKaggle").SetServerAPIOptions(serverAPI)

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

func InitDocker() {
	var err error
	dockerClient, err = client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}
	dockerClient.NegotiateAPIVersion(context.Background())
	log.Println("Docker client initialized!")
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
	codesCollection := database.Collection("compiler")

	insertResult, err := codesCollection.InsertOne(context.TODO(), payload)
	if err != nil {
		http.Error(w, "Failed to save snippet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Code saved successfully, ID: %v", insertResult.InsertedID)
}

type ExecutePayload struct {
	Email string `json:"email"`
	Code  string `json:"code"`
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

	log.Printf("Received execution request.")

	if payload.Email == "" {
		http.Error(w, "User email missing in request", http.StatusUnauthorized)
		return
	}

	containerIDValue, ok := userContainers.Load(payload.Email)
	if !ok {
		http.Error(w, "No container initialized for user", http.StatusInternalServerError)
		return
	}

	containerID := containerIDValue.(string)

	if err := copyCodeToContainer(dockerClient, context.Background(), containerID, payload.Code, "main.go"); err != nil {
		http.Error(w, "Failed to copy code to container", http.StatusInternalServerError)
		return
	}

	output, err := runCodeInExistingContainer(containerID)
	if err != nil {
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

func runCodeInExistingContainer(containerID string) (string, error) {
	ctx := context.Background()

	execResp, err := dockerClient.ContainerExecCreate(ctx, containerID, types.ExecConfig{
		Cmd:          []string{"go", "run", "main.go"},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", err
	}

	attachResp, err := dockerClient.ContainerExecAttach(ctx, execResp.ID, types.ExecStartCheck{})
	if err != nil {
		return "", err
	}
	defer attachResp.Close()

	var stdoutBuf bytes.Buffer
	_, err = io.Copy(&stdoutBuf, attachResp.Reader)
	if err != nil {
		return "", err
	}

	inspectResp, err := dockerClient.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return "", err
	}

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

// func cleanupContainer(cli *client.Client, ctx context.Context, containerID string) {
// 	cli.ContainerStop(ctx, containerID, container.StopOptions{})
// 	cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
// 		Force: true,
// 	})
// }

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
	usersCollection := database.Collection("users")

	insertResult, err := usersCollection.InsertOne(context.TODO(), payload)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User saved successfully, ID: %v", insertResult.InsertedID)
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

	ctx := context.Background()
	image := "golang:1.20-alpine"

	_, err = dockerClient.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		http.Error(w, "Failed to pull Docker image", http.StatusInternalServerError)
		return
	}

	resp, err := dockerClient.ContainerCreate(ctx,
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
		http.Error(w, "Failed to create container", http.StatusInternalServerError)
		return
	}

	if err := dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		http.Error(w, "Failed to start container", http.StatusInternalServerError)
		return
	}

	userContainers.Store(payload.Email, resp.ID)

	response := map[string]string{
		"status":  "success",
		"message": "Login successful",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Hello World!")
}

func main() {
	InitDB()
	InitDocker()

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
