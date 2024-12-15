use actix_web::{HttpResponse, Responder, post, web};
use mongodb::{Client, Collection, bson::doc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Deserialize, Serialize)]
pub struct NewCodePayload {
    pub email: String,
    pub filename: String,
    pub code: String,
}

#[post("/new")]
pub async fn new_handler(
    db: web::Data<Client>,
    payload: web::Json<NewCodePayload>,
) -> impl Responder {
    let codes_collection: Collection<NewCodePayload> = db.database("gokaggle").collection("codes");

    let filter = doc! {
        "email": &payload.email,
        "filename": &payload.filename,
    };

    match codes_collection.find_one(filter).await {
        Ok(Some(_)) => {
            return HttpResponse::Conflict()
                .body("File with the same name already exists for this user");
        }
        Ok(None) => {}
        Err(err) => {
            error!("Error checking for existing file: {:?}", err);
            return HttpResponse::InternalServerError().body("Error checking for existing file");
        }
    }

    let doc = NewCodePayload {
        email: payload.email.clone(),
        filename: payload.filename.clone(),
        code: payload.code.clone(),
    };

    match codes_collection.insert_one(doc).await {
        Ok(insert_result) => {
            info!(
                "New code snippet saved, ID: {:?}",
                insert_result.inserted_id
            );
            HttpResponse::Created().body(format!(
                "Code saved successfully, ID: {:?}",
                insert_result.inserted_id
            ))
        }
        Err(err) => {
            error!("Failed to save code snippet: {:?}", err);
            HttpResponse::InternalServerError().body("Failed to save code snippet")
        }
    }
}
