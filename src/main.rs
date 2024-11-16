use std::sync::Mutex;
use actix_web::middleware::Logger;
use r2d2::Pool;
use rusqlite::Result;
use r2d2_sqlite::SqliteConnectionManager;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use tokio::time;
use tracing::info;
use tracing_actix_web::TracingLogger;

mod app_state;
use crate::app_state::AppState;

mod handlers;
use crate::handlers::users;

mod middleware;
use crate::middleware::auth::Authentication;


#[get("/")]
async fn index(data: web::Data<AppState>) -> String {
	let counter = {
		let mut counter = data.counter.lock().unwrap(); // <- get counter's MutexGuard
		*counter += 1; // <- access counter inside MutexGuard
		*counter
	};
	let app_name = &data.app_name.clone(); // <- get app_name
	// let app_counter = *data.counter.read().unwrap(); // <- get counter's MutexGuard

	// read users from db
	// let pool = data.db_connection_pool.clone();
	// let users = web::block(move || {
	// 	let conn = data.db_connection_pool.get().unwrap();
	// 	let mut stmt = conn.prepare("SELECT id, name, email, password FROM users").unwrap();
	// 	let users = stmt.query_map([], |row| {
	// 		Ok(User {
	// 			id: row.get(0)?,
	// 			name: row.get(1)?,
	// 			email: row.get(2)?,
	// 			password: row.get(3)?
	// 		})
	// 	}).unwrap();

	// 	// create string with one user per line
	// 	users.map(|user| {
	// 		let user = user.unwrap();
	// 		format!("{} {} {} {}", user.id, user.name, user.email, user.password)
	// 	}).collect::<Vec<String>>().join("\n")
	// }).await.unwrap();

	time::sleep(std::time::Duration::from_secs(5)).await;

	format!("Hello {}! Request number: {}", app_name, counter) // <- response with app_name
}

// #[derive(Deserialize)]
// struct UserRequest {
// 	name: String,
// 	email: String,
// 	password: String
// }


#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
	info!("request body: {}", req_body);
	HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
	HttpResponse::Ok().body("Hey there!")
}

async fn init_db(pool: &Pool<SqliteConnectionManager>) -> Result<()> {
	let conn = pool.get().unwrap();
	match conn.execute(
		"CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		)",
		[],
	) {
		Ok(_) => (),
		Err(e) => panic!("Error creating table users: {}", e)
	};

	// insert 3 users
	// match conn.execute(
	// 	"INSERT INTO users (name, email, password) VALUES (?1, ?2, ?3), (?4, ?5, ?6), (?7, ?8, ?9)",
	// 	["John", "john@example.com", "password", "Jane", "jane@example.com", "password", "Joe", "joe@example.com", "password"],
	// ) {
	// 	Ok(_) => (),
	// 	Err(e) => panic!("Error inserting user: {}", e)
	// };

	Ok(())
}

#[get("/test")]
async fn test() -> impl Responder {
	tokio::time::sleep(std::time::Duration::from_secs(5)).await;
	"response"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let manager = SqliteConnectionManager::file("test.db");
	let pool = r2d2::Pool::builder().max_size(15).build(manager).unwrap();

	init_db(&pool).await.unwrap();

	let counter = web::Data::new(app_state::AppState {
		app_name: String::from("Actix-web"),
		counter: Mutex::new(0),
		db_connection_pool: pool,
	});

	env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

	HttpServer::new(move || {
		App::new()
			.app_data(counter.clone())
			// .wrap_fn(|req, srv| {
			// 	println!("Requested started");
			// 	let start = std::time::Instant::now();
			// 	let request = req.method().to_string() + " " + req.uri().to_string().as_str() + " " + req.query_string();
			// 	srv.call(req).map(move |res| {
			// 		let elapsed = start.elapsed();
			// 		let now = chrono::Utc::now();
			// 		println!("{}: duration={:?}, request=\"{}\"", now.to_rfc3339(), elapsed, request);
			// 		res
			// 	})
			// })
			.wrap(Logger::default())
			.wrap(Authentication)
			// .wrap(TracingLogger::default())
			.service(index)
			.service(echo)
			.service(users::new("/users"))
			.service(test)
			.route("/hey", web::get().to(manual_hello))
	})
	.bind(("127.0.0.1", 8080))?
	.run()
	.await
}