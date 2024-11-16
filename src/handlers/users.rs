use actix_web::{get, post, web::{self, Json}, Responder, middleware::{ErrorHandlers, ErrorHandlerResponse, Logger}, Result, dev, http::{header, StatusCode}, HttpResponse};
use serde::{Deserialize, Serialize};
use bcrypt::{DEFAULT_COST, hash, verify};
use tracing::debug;

use crate::{app_state::AppState, middleware::auth::Claims};
use crate::middleware::auth::generate_token;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct User {
	pub id: i32,
	pub name: String,
	pub email: String,
	pub password: String
}

#[derive(Deserialize)]
struct GetUserRequest {
	user_id: i32
}

// get user by id and return as json
async fn get_user(data: web::Data<AppState>, info: web::Path<GetUserRequest>) -> actix_web::Result<impl Responder> {
	let conn = data.db_connection_pool.get().unwrap();

	// wrap in web::block to offload blocking sql code without blocking server thread
	let user = web::block(move || {
		let mut stmt = conn.prepare("SELECT id, name, email, password FROM users WHERE id = ?1").unwrap();
		stmt.query_row([info.user_id], |row| {
			Ok(User {
				id: row.get(0)?,
				name: row.get(1)?,
				email: row.get(2)?,
				password: row.get(3)?
			})
		})
	}).await.unwrap();

	let user = match user {
		Ok(user) => user,
		Err(e) => return Err(actix_web::error::ErrorNotFound(e))
	};

	Ok(Json(user))
}

#[derive(Deserialize)]
struct UserAuthRequest {
	email: String,
	password: String
}

async fn user_authenticate(data: web::Data<AppState>, credentials: Json<UserAuthRequest>) -> actix_web::Result<impl Responder> {
	let conn = data.db_connection_pool.get().unwrap();

	#[derive(Debug, Serialize, Deserialize, PartialEq)]
	struct User {
		id: i32,
		name: String,
		email: String,
		password: String,
		token: String
	}

	let received_password = credentials.password.clone();
	// wrap in web::block to offload blocking sql code without blocking server thread
	let user = web::block(move || {
		let mut stmt = conn.prepare("SELECT id, name, email, password FROM users WHERE email = ?1").unwrap();
		stmt.query_row([&credentials.email], |row| {
			Ok(User {
				id: row.get(0)?,
				name: row.get(1)?,
				email: row.get(2)?,
				password: row.get(3)?,
				token: String::from(""),
			})
		})
	}).await.unwrap();

	debug!("user: {:?}", user);

	let mut user = match user {
		Ok(user) => user,
		Err(e) => return Err(actix_web::error::ErrorNotFound(e))
	};

	// verify password
	let is_valid = verify(&received_password, &user.password).unwrap();
	if !is_valid {
		return Err(actix_web::error::ErrorUnauthorized("Invalid password"));
	}

	// generate token
	let token = match generate_token(Claims::new(user.id, 1)) {
		Ok(token) => token,
		Err(e) => return Err(actix_web::error::ErrorInternalServerError(e))
	};
	user.token = token;

	Ok(Json(user))
}

// post user to db
async fn post_user(data: web::Data<AppState>, user: Json<User>) -> impl Responder {
	let conn = data.db_connection_pool.get().unwrap();

	// wrap in web::block to offload blocking sql code without blocking server thread
	let user = web::block(move || {
		// hash password
		let hashed_password = hash(&user.password, DEFAULT_COST).unwrap();
		conn.execute(
			"INSERT INTO users (name, email, password) VALUES (?1, ?2, ?3)",
			rusqlite::params![&user.name, &user.email, &hashed_password],
		).unwrap();
		let id = conn.last_insert_rowid();

		let mut stmt = conn.prepare("SELECT id, name, email, password FROM users WHERE id = ?").unwrap();
		stmt.query_row([&id], |row| {
			Ok(User {
				id: row.get(0)?,
				name: row.get(1)?,
				email: row.get(2)?,
				password: row.get(3)?
			})
		})
	}).await.unwrap();

	let user = match user {
		Ok(user) => user,
		Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e))
	};

	HttpResponse::Ok().json(user)
}

// delete user from db
async fn delete_user(data: web::Data<AppState>, info: web::Path<GetUserRequest>) -> impl Responder {
	let conn = data.db_connection_pool.get().unwrap();

	// wrap in web::block to offload blocking sql code without blocking server thread
	let result = web::block(move || {
		let mut stmt = conn.prepare("DELETE FROM users WHERE id = ?1").unwrap();
		match stmt.execute([&info.user_id]) {
			Ok(1) => Ok(()),
			Ok(_) => Err(rusqlite::Error::QueryReturnedNoRows),
			Err(e) => Err(e)
		}
	}).await.unwrap();

	match result {
		Ok(_) => HttpResponse::Ok().body("User deleted"),
		Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e))
	}
}

pub fn new(path: &str) -> actix_web::Scope {
	web::scope(path)
	.service(web::resource("/auth").route(web::post().to(user_authenticate)).wrap(Logger::default()))
	.service(web::resource("/{user_id}")
		.route(web::get().to(get_user)).wrap(Logger::default())
		.route(web::delete().to(delete_user).wrap(Logger::default()))
	)
	.service(web::resource("/").route(web::post().to(post_user)).wrap(Logger::default()))
	// .service(web::resource("/delete/{user_id}").route(web::delete().to(delete_user)).wrap(Logger::default()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use actix_web::{test, App};
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    #[actix_web::test]
    async fn test_get_user() {
        // 1. Create a mock database connection pool.
        let manager = SqliteConnectionManager::file(":memory:");
		let pool = Pool::new(manager).expect("Failed to create pool.");

		// 2. Insert a user into the mock database.
		let user = User {
			id: 1,
			name: "Test User".to_string(),
			email: "test@example.com".to_string(),
			password: "password".to_string(),
		};

		{
			let conn = pool.get().unwrap();
			conn.execute(
				"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT)",
				[],
			).unwrap();

			conn.execute(
				"INSERT INTO users (id, name, email, password) VALUES (?1, ?2, ?3, ?4)",
				rusqlite::params![&user.id, &user.name, &user.email, &user.password],
			).unwrap();
		}

		let state = web::Data::new(AppState {
			app_name: String::from("Actix-web"),
			counter: Mutex::new(0),
			db_connection_pool: pool,
		});

        // 3. Call the get_user function with the id of the inserted user.
        let app = test::init_service(
            App::new()
                .app_data(state.clone())
                .service(new("/users")),
        ).await;
        let req = test::TestRequest::with_uri("/users/1").to_request();
        let resp = test::call_service(&app, req).await;

		assert!(resp.status().is_success(), "Response error: {:?}", resp);

        // 4. Assert that the returned user matches the one we inserted.
        let resp_user: User = test::read_body_json(resp).await;
        assert_eq!(resp_user, user);
    }
}
