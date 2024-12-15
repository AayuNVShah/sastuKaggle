use anyhow::Result;
use mongodb::{
    Client,
    bson::doc,
    options::{ClientOptions, ServerApi, ServerApiVersion},
};
use tracing::info;

const URI: &str = "mongodb+srv://khwahish:khwahish29@sastukaggle.2kw7w.mongodb.net/?retryWrites=true&w=majority&appName=sastuKaggle";

pub async fn init_db() -> Result<Client> {
    let mut client_options = ClientOptions::parse(URI).await?;

    // Set the server_api field of the client_options object to Stable API version 1
    let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
    client_options.server_api = Some(server_api);

    // Create a new client and connect to the server
    let client = Client::with_options(client_options)?;

    // Send a ping to confirm successful connection
    client
        .database("admin")
        .run_command(doc! {"ping": 1})
        .await?;

    info!("Successfully connected to MongoDB");

    Ok(client)
}
