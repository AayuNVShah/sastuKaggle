package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// -------------------------------- DB Connections and Functions --------------------------------
var client *mongo.Client

func InitDB() {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI("mongodb+srv://dhairyas4:PJgCjCjuFsD80A6H@cluster0.bcucc.mongodb.net/Compiler?retryWrites=true&w=majority&appName=Cluster0").SetServerAPIOptions(serverAPI)

	var err error
	client, err = mongo.Connect(context.TODO(), opts)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	if err := client.Database("admin").RunCommand(context.TODO(), primitive.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}
	log.Println("Connected to MongoDB!")
}

func CloseDB() {
	if err := client.Disconnect(context.TODO()); err != nil {
		log.Fatalf("Failed to disconnect from MongoDB: %v", err)
	}
}

// -------------------------------- API Payloads & Handlers --------------------------------

type newCodePayload struct {
	FileName string `json:"file_name"`
	Code     string `json:"code"`
}

func SaveSnippetHandler(w http.ResponseWriter, r *http.Request) {
	var payload newCodePayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	database := client.Database("Compiler")
	snippetsCollection := database.Collection("Storage")

	insertResult, err := snippetsCollection.InsertOne(context.TODO(), payload)
	if err != nil {
		http.Error(w, "Failed to save snippet", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Code saved successfully, ID: %v", insertResult.InsertedID)
}

func main() {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", helloWorldHandler)

	http.ListenAndServe(":3333", r)
}

func helloWorldHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Hello World!")
}
