use std::sync::Mutex;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub struct AppState {
	pub app_name: String,
	pub counter: Mutex<i32>,
	pub db_connection_pool: Pool<SqliteConnectionManager>
}
