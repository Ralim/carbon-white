use crate::{components::header::Header, pages::footer::Footer};
use leptos::prelude::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub auth_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub token: Option<String>,
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let (auth_key, set_auth_key) = signal(String::new());
    let (is_logging_in, set_is_logging_in) = signal(false);
    let (error_message, set_error_message) = signal(Option::<String>::None);
    let (success_message, set_success_message) = signal(Option::<String>::None);

    let (is_authenticated, set_is_authenticated) = signal(false);

    // Check if user is authenticated on page load
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        use crate::shared::AuthStatusResponse;
        use leptos::task::spawn_local;
        spawn_local(async move {
            // Get auth token from localStorage
            let token = if let Some(window) = web_sys::window() {
                if let Some(storage) = window.local_storage().unwrap_or(None) {
                    storage.get_item("carbon_auth_token").unwrap_or(None)
                } else {
                    None
                }
            } else {
                None
            };

            let mut request = gloo_net::http::Request::get("/api/auth/status");

            // Add Authorization header if token exists
            if let Some(token) = token {
                request = request.header("Authorization", &format!("Bearer {}", token));
            }

            // Check auth status by making a simple request to a protected endpoint
            match request.send().await {
                Ok(response) => match response.json::<AuthStatusResponse>().await {
                    Ok(data) => set_is_authenticated.set(data.authenticated),
                    Err(_) => set_is_authenticated.set(false),
                },
                Err(_) => {
                    set_is_authenticated.set(false);
                }
            }
        });
    });

    let navigate = hooks::use_navigate();

    // Remove Action::new, handle submission with spawn_local
    let handle_submit = {
        let navigate = navigate.clone();
        move |_| {
            let auth_key_value = auth_key.get();
            let set_is_logging_in = set_is_logging_in;
            let set_error_message = set_error_message;
            let set_success_message = set_success_message;
            let navigate = navigate.clone();

            #[cfg(feature = "hydrate")]
            leptos::task::spawn_local(async move {
                use gloo_timers::callback::Timeout;

                if auth_key_value.trim().is_empty() {
                    set_error_message.set(Some("Please enter an authentication key".to_string()));
                    return;
                }

                set_is_logging_in.set(true);
                set_error_message.set(None);
                set_success_message.set(None);

                let login_request = LoginRequest {
                    auth_key: auth_key_value,
                };

                match perform_login(login_request).await {
                    Ok(response) => {
                        if response.success {
                            // Store the token in localStorage
                            if let Some(token) = response.token {
                                if let Some(window) = web_sys::window() {
                                    if let Some(storage) = window.local_storage().unwrap_or(None) {
                                        let _ = storage.set_item("carbon_auth_token", &token);
                                    }
                                }
                            }
                            set_success_message
                                .set(Some("Login successful! Redirecting...".to_string()));
                            // Redirect to home page after successful login

                            Timeout::new(1500, move || {
                                navigate("/", Default::default());
                            })
                            .forget();
                        } else {
                            set_error_message.set(Some(response.message));
                        }
                    }
                    Err(e) => {
                        set_error_message.set(Some(format!("Login failed: {}", e)));
                    }
                }
                set_is_logging_in.set(false);
            });
            #[cfg(not(feature = "hydrate"))]
            {
                set_error_message.set(Some(
                    "Client-side functionality not available in SSR".to_string(),
                ));
                set_is_logging_in.set(false);
            }
        }
    };

    view! {
        <div class="app-container">
            <Header is_authenticated/>

            <div class="login-content">
                <div class="login-container">
                    <h1 class="login-title">"Login to Carbon White"</h1>

                    <form
                        class="login-form"
                        on:submit=move |ev| {
                            ev.prevent_default();
                            handle_submit(());
                        }
                    >
                        <div class="form-group">
                            <label for="auth_key" class="form-label">
                                "Authentication Key"
                            </label>
                            <input
                                type="password"
                                id="auth_key"
                                name="auth_key"
                                class="form-input"
                                placeholder="Enter your authentication key"
                                prop:value=auth_key
                                on:input=move |ev| {
                                    set_auth_key.set(event_target_value(&ev));
                                }
                                prop:disabled=is_logging_in
                            />
                        </div>

                        <Show
                            when=move || error_message.get().is_some()
                            fallback=|| view! { <div></div> }
                        >
                            <div class="error-message">
                                {move || error_message.get().unwrap_or_default()}
                            </div>
                        </Show>

                        <Show
                            when=move || success_message.get().is_some()
                            fallback=|| view! { <div></div> }
                        >
                            <div class="success-message">
                                {move || success_message.get().unwrap_or_default()}
                            </div>
                        </Show>

                        <button
                            type="submit"
                            class="login-button"
                            prop:disabled=is_logging_in
                        >
                            <Show
                                when=move || is_logging_in.get()
                                fallback=|| view! { "Login" }
                            >
                                "Logging in..."
                            </Show>
                        </button>
                    </form>

                    <div class="login-info">
                        <p class="info-text">
                            "Access to Carbon White requires a valid authentication key. "
                            "Contact your administrator if you need access."
                        </p>
                    </div>
                </div>
            </div>

            <Footer/>
        </div>
    }
}

#[cfg(feature = "hydrate")]
async fn perform_login(request: LoginRequest) -> Result<LoginResponse, String> {
    let response = gloo_net::http::Request::post("/api/auth")
        .json(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !response.ok() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Login failed ({}): {}", status, error_text));
    }

    response
        .json::<LoginResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_request_creation() {
        let request = LoginRequest {
            auth_key: "test_key".to_string(),
        };

        assert_eq!(request.auth_key, "test_key");
    }

    #[test]
    fn test_login_response_creation() {
        let response = LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            token: Some("test_token".to_string()),
        };

        assert!(response.success);
        assert_eq!(response.message, "Login successful");
        assert_eq!(response.token.unwrap(), "test_token");
    }

    #[test]
    fn test_login_response_failure() {
        let response = LoginResponse {
            success: false,
            message: "Invalid auth key".to_string(),
            token: None,
        };

        assert!(!response.success);
        assert_eq!(response.message, "Invalid auth key");
        assert!(response.token.is_none());
    }
}
