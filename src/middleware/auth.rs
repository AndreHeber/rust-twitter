use std::future::{ready, Ready};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, error::ErrorUnauthorized, HttpMessage,
};
use chrono::{Utc, Duration};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, errors::ErrorKind, encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};

use crate::handlers::users::User;

pub struct Authentication;

impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware { service }))
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req.headers().get("Authorization");

        // Verify the Authorization header and get the user
        let user = match auth_header {
            Some(header_value) => {
                let auth_str = header_value.to_str().unwrap_or("");
                verify_auth(auth_str)
            }
            None => Err("Authorization header is missing"),
        };

        match user {
            Ok(user) => {
                req.extensions_mut().insert(user);
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })
            }
            Err(e) => Box::pin(async move { Err(ErrorUnauthorized(e)) }),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
	user_id: i32,
	client_id: i32,
	sub: String,
	exp: usize
}

// implement function new for Claims
impl Claims {
	pub fn new(user_id: i32, client_id: i32) -> Self {
		Self {
			user_id,
			client_id,
			sub: "andre.heber@gmx.net".to_owned(),
			exp: (Utc::now() + Duration::weeks(1)).timestamp() as usize
		}
	}
}

pub fn generate_token(claims: Claims) -> Result<String, &'static str> {
	let key = b"dhfg8765bjngvkfd.sgb,ds.l";
	// let my_claims = Claims {
	// 	user_id: 1,
	// 	client_id: 1,
	// 	sub: "andre.heber@gmx.net".to_owned(),
	// 	exp: 10000000000,
	// };

	let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(key)) {
		Ok(token) => token,
		Err(_) => return Err("Error encoding token")
	};

	Ok("Bearer ".to_owned() + &token)
}

fn verify_auth(auth_str: &str) -> Result<Claims, &'static str> {
	let key = b"dhfg8765bjngvkfd.sgb,ds.l";

	let token = match auth_str.strip_prefix("Bearer ") {
        Some(token) => token,
        None => return Err("Invalid token format"),
    };
	
	let mut validation = Validation::new(Algorithm::HS256);
    validation.sub = Some("andre.heber@gmx.net".to_string());
	let token_data = match decode::<Claims>(token, &DecodingKey::from_secret(key), &validation) {
		Ok(token_data) => token_data,
		Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
            _ => panic!("Some other errors"),
        },
	};

	Ok(token_data.claims)

    // // Verify the auth_str and return a User
    // // This is just a placeholder implementation
    // if auth_str == "valid_token" {
    //     Ok(User {
    //         id: 1,
    //         name: "Test".to_string(),
    //         email: "test@example.com".to_string(),
    //         password: "hashed_password".to_string(),
    //     })
    // } else {
    //     Err("Invalid token")
    // }
}