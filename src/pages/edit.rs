use crate::{components::header::Header, pages::footer::Footer, shared::AuthStatusResponse};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_navigate, hooks::use_params_map};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub id: i64,
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
    pub file_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateDocumentRequest {
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
}

#[component]
pub fn EditPage() -> impl IntoView {
    let params = use_params_map();
    let navigate = use_navigate();
    let navigate_stored = StoredValue::new(navigate.clone());

    let (is_authenticated, _set_is_authenticated) = signal(false);
    let (is_loading, _set_is_loading) = signal(true);
    let (is_updating, _set_is_updating) = signal(false);
    let (error_message, _set_error_message) = signal(Option::<String>::None);
    let (success_message, _set_success_message) = signal(Option::<String>::None);
    let (document, _set_document) = signal(Option::<Document>::None);

    // Form fields
    let (title, set_title) = signal(String::new());
    let (part_number, set_part_number) = signal(String::new());
    let (manufacturer, set_manufacturer) = signal(String::new());
    let (document_id, set_document_id) = signal(String::new());
    let (document_version, set_document_version) = signal(String::new());
    let (package_marking, set_package_marking) = signal(String::new());
    let (device_address, set_device_address) = signal(String::new());
    let (notes, set_notes) = signal(String::new());

    // Check authentication and load document on page load
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        use leptos::task::spawn_local;

        let navigate = navigate.clone();
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

            // Check auth status
            match request.send().await {
                Ok(response) => {
                    match response.json::<AuthStatusResponse>().await {
                        Ok(data) => {
                            if data.authenticated {
                                _set_is_authenticated.set(true);

                                // Load document data
                                if let Some(sha256) = params.get().get("sha256") {
                                    match load_document(&sha256).await {
                                        Ok(doc) => {
                                            set_title.set(doc.title.clone());
                                            set_part_number
                                                .set(doc.part_number.clone().unwrap_or_default());
                                            set_manufacturer
                                                .set(doc.manufacturer.clone().unwrap_or_default());
                                            set_document_id
                                                .set(doc.document_id.clone().unwrap_or_default());
                                            set_document_version.set(
                                                doc.document_version.clone().unwrap_or_default(),
                                            );
                                            set_package_marking.set(
                                                doc.package_marking.clone().unwrap_or_default(),
                                            );
                                            set_device_address.set(
                                                doc.device_address.clone().unwrap_or_default(),
                                            );
                                            set_notes.set(doc.notes.clone().unwrap_or_default());
                                            _set_document.set(Some(doc));
                                        }
                                        Err(e) => {
                                            _set_error_message.set(Some(format!(
                                                "Failed to load document: {}",
                                                e
                                            )));
                                        }
                                    }
                                }
                            } else {
                                // Redirect to login if not authenticated
                                navigate("/login", Default::default());
                            }
                        }
                        Err(_) => {
                            // Redirect to login on error
                            navigate("/login", Default::default());
                        }
                    }
                }
                Err(_) => {
                    // Redirect to login on error
                    navigate("/login", Default::default());
                }
            }

            _set_is_loading.set(false);
        });
    });

    view! {
        <div class="app-container">
            <Header is_authenticated/>

            <Show
                when=move || !is_loading.get() && is_authenticated.get()
                fallback=|| view! {
                    <div class="loading-container">
                        <div class="loading-message">"Loading document..."</div>
                    </div>
                }
            >
                <div class="submit-content">
                    <div class="submit-container">
                        <h1 class="submit-title">"Edit Document"</h1>

                        <Show
                            when=move || document.get().is_some()
                            fallback=|| view! {
                                <div class="error-message">
                                    "Document not found"
                                </div>
                            }
                        >
                            <form
                                class="submit-form"
                                on:submit=move |ev| {
                                    ev.prevent_default();
                                    #[cfg(feature = "hydrate")]
                                    {
                                        if let Some(sha256) = params.get().get("sha256") {
                                            let request_data = UpdateDocumentRequest {
                                                title: title.get(),
                                                part_number: if part_number.get().trim().is_empty() { None } else { Some(part_number.get()) },
                                                manufacturer: if manufacturer.get().trim().is_empty() { None } else { Some(manufacturer.get()) },
                                                document_id: if document_id.get().trim().is_empty() { None } else { Some(document_id.get()) },
                                                document_version: if document_version.get().trim().is_empty() { None } else { Some(document_version.get()) },
                                                package_marking: if package_marking.get().trim().is_empty() { None } else { Some(package_marking.get()) },
                                                device_address: if device_address.get().trim().is_empty() { None } else { Some(device_address.get()) },
                                                notes: if notes.get().trim().is_empty() { None } else { Some(notes.get()) },
                                            };

                                            let nav = navigate_stored.get_value();
                                            wasm_bindgen_futures::spawn_local(async move {
                                                _set_is_updating.set(true);
                                                _set_error_message.set(None);
                                                _set_success_message.set(None);

                                                match update_document(&sha256, request_data).await {
                                                    Ok(response) => {
                                                        if response.success {
                                                            _set_success_message.set(Some(response.message));
                                                            // Navigate back to home page after successful update with brief delay
                                                            let nav_clone = nav.clone();
                                                            gloo_timers::callback::Timeout::new(1500, move || {
                                                                nav_clone("/", Default::default());
                                                            }).forget();
                                                        } else {
                                                            _set_error_message.set(Some(response.message));
                                                        }
                                                    }
                                                    Err(e) => {
                                                        _set_error_message.set(Some(format!("Update failed: {}", e)));
                                                    }
                                                }
                                                _set_is_updating.set(false);
                                            });
                                        }
                                    }
                                }
                            >
                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="title" class="form-label required">
                                            "Title *"
                                        </label>
                                        <input
                                            type="text"
                                            id="title"
                                            name="title"
                                            class="form-input"
                                            placeholder="Document title"
                                            prop:value=title
                                            on:input=move |ev| {
                                                set_title.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                            required
                                        />
                                    </div>

                                    <div class="form-group">
                                        <label for="part_number" class="form-label">
                                            "Part Number"
                                        </label>
                                        <input
                                            type="text"
                                            id="part_number"
                                            name="part_number"
                                            class="form-input"
                                            placeholder="Part number"
                                            prop:value=part_number
                                            on:input=move |ev| {
                                                set_part_number.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>
                                </div>

                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="manufacturer" class="form-label">
                                            "Manufacturer"
                                        </label>
                                        <input
                                            type="text"
                                            id="manufacturer"
                                            name="manufacturer"
                                            class="form-input"
                                            placeholder="Manufacturer name"
                                            prop:value=manufacturer
                                            on:input=move |ev| {
                                                set_manufacturer.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>

                                    <div class="form-group">
                                        <label for="document_id" class="form-label">
                                            "Document ID"
                                        </label>
                                        <input
                                            type="text"
                                            id="document_id"
                                            name="document_id"
                                            class="form-input"
                                            placeholder="Document ID"
                                            prop:value=document_id
                                            on:input=move |ev| {
                                                set_document_id.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>
                                </div>

                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="document_version" class="form-label">
                                            "Document Version"
                                        </label>
                                        <input
                                            type="text"
                                            id="document_version"
                                            name="document_version"
                                            class="form-input"
                                            placeholder="Version"
                                            prop:value=document_version
                                            on:input=move |ev| {
                                                set_document_version.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>

                                    <div class="form-group">
                                        <label for="package_marking" class="form-label">
                                            "Package Marking"
                                        </label>
                                        <input
                                            type="text"
                                            id="package_marking"
                                            name="package_marking"
                                            class="form-input"
                                            placeholder="Package marking"
                                            prop:value=package_marking
                                            on:input=move |ev| {
                                                set_package_marking.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>
                                </div>

                                <div class="form-row">
                                    <div class="form-group">
                                        <label for="device_address" class="form-label">
                                            "Device Address"
                                        </label>
                                        <input
                                            type="text"
                                            id="device_address"
                                            name="device_address"
                                            class="form-input"
                                            placeholder="Device address (e.g., 0x48)"
                                            prop:value=device_address
                                            on:input=move |ev| {
                                                set_device_address.set(event_target_value(&ev));
                                            }
                                            prop:disabled=is_updating
                                        />
                                    </div>

                                    <div class="form-group file-info">
                                        <label class="form-label">
                                            "Attached File"
                                        </label>
                                        <div class="file-display">
                                            {move || {
                                                document.get().map(|doc| doc.original_file_name).unwrap_or_default()
                                            }}
                                        </div>
                                        <p class="file-note">"File cannot be changed when editing"</p>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label for="notes" class="form-label">
                                        "Notes"
                                    </label>
                                    <textarea
                                        id="notes"
                                        name="notes"
                                        class="form-input form-textarea"
                                        placeholder="Additional notes or comments"
                                        prop:value=notes
                                        on:input=move |ev| {
                                            set_notes.set(event_target_value(&ev));
                                        }
                                        prop:disabled=is_updating
                                        rows="4"
                                    ></textarea>
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

                                <div class="form-actions">
                                    <button
                                        type="submit"
                                        class="submit-button"
                                        prop:disabled=is_updating
                                    >
                                        <Show
                                            when=move || is_updating.get()
                                            fallback=|| view! { "Update Document" }
                                        >
                                            "Updating..."
                                        </Show>
                                    </button>

                                    <A href="/" attr:class="cancel-button">
                                        "Cancel"
                                    </A>
                                </div>
                            </form>
                        </Show>

                        <div class="submit-info">
                            <p class="info-text">
                                "* Required fields. File attachments cannot be changed when editing."
                            </p>
                        </div>
                    </div>
                </div>
            </Show>

            <Footer/>
        </div>
    }
}

#[cfg(feature = "hydrate")]
async fn load_document(sha256: &str) -> Result<Document, String> {
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

    let mut request = gloo_net::http::Request::get(&format!("/api/document/{}", sha256));

    // Add Authorization header if token exists
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {}", token));
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !response.ok() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!(
            "Failed to load document ({}): {}",
            status, error_text
        ));
    }

    response
        .json::<Document>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

#[cfg(feature = "hydrate")]
async fn update_document(
    sha256: &str,
    request_data: UpdateDocumentRequest,
) -> Result<UpdateResponse, String> {
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

    let mut request = gloo_net::http::Request::put(&format!("/api/document/{}", sha256));

    // Add Authorization header if token exists
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {}", token));
    }

    let response = request
        .json(&request_data)
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
        return Err(format!("Update failed ({}): {}", status, error_text));
    }

    response
        .json::<UpdateResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}
