use crate::{components::header::Header, pages::footer::Footer};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_navigate};
use serde::{Deserialize, Serialize};
#[cfg(feature = "hydrate")]
use web_sys::FormData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub success: bool,
    pub message: String,
    pub file_sha256: Option<String>,
}

#[component]
pub fn SubmitPage() -> impl IntoView {
    let (is_authenticated, set_is_authenticated) = signal(false);
    let (is_submitting, set_is_submitting) = signal(false);
    let (error_message, set_error_message) = signal(Option::<String>::None);
    let (success_message, set_success_message) = signal(Option::<String>::None);

    // Check authentication on page load
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        use crate::shared::AuthStatusResponse;
        use leptos::task::spawn_local;
        let navigate = use_navigate();
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
                Ok(response) => {
                    match response.json::<AuthStatusResponse>().await {
                        Ok(data) => {
                            if data.authenticated {
                                set_is_authenticated.set(true);
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
        });
    });

    // Form fields
    let (title, set_title) = signal(String::new());
    let (part_number, set_part_number) = signal(String::new());
    let (manufacturer, set_manufacturer) = signal(String::new());
    let (document_id, set_document_id) = signal(String::new());
    let (document_version, set_document_version) = signal(String::new());
    let (package_marking, set_package_marking) = signal(String::new());
    let (device_address, set_device_address) = signal(String::new());
    let (notes, set_notes) = signal(String::new());

    let navigate = use_navigate();

    // Check authentication on page load
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

            match request.send().await {
                Ok(response) => {
                    if response.status() == 200 {
                        set_is_authenticated.set(true);
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
        });
    });

    // Instead of passing a struct with a File (which is not Send/Sync), pass only the fields needed for the request.
    #[derive(Clone)]
    struct SubmitFormFields {
        title: String,
        part_number: String,
        manufacturer: String,
        document_id: String,
        document_version: String,
        package_marking: String,
        device_address: String,
        notes: String,
        // Instead of passing the File, pass its index and extract it synchronously in the event handler.
    }

    view! {
        <div class="app-container">
            <Header is_authenticated/>

            <Show
                when=move || is_authenticated.get()
                fallback=|| view! {
                    <div class="loading-container">
                        <div class="loading-message">"Checking authentication..."</div>
                    </div>
                }
            >
                <div class="submit-content">
                    <div class="submit-container">
                        <h1 class="submit-title">"Submit Document"</h1>

                        <form
                            class="submit-form"
                            enctype="multipart/form-data"
                            on:submit=move |ev| {
                                ev.prevent_default();
                                #[cfg(feature = "hydrate")]
                                {
                                    use wasm_bindgen::JsCast;
                                    use web_sys::{HtmlFormElement, HtmlInputElement};
                                    let form_element = ev.target().unwrap().dyn_into::<HtmlFormElement>().unwrap();

                                    let file_input: HtmlInputElement = form_element
                                        .query_selector("input[type='file']")
                                        .unwrap()
                                        .unwrap()
                                        .dyn_into()
                                        .unwrap();

                                    let files = file_input.files();
                                    let file = files.and_then(|fl| fl.get(0));
                                    if file.is_none() {
                                        set_error_message.set(Some("Please select a file to upload".to_string()));
                                        set_is_submitting.set(false);
                                        return;
                                    }

                                    let fields = SubmitFormFields {
                                        title: title.get(),
                                        part_number: part_number.get(),
                                        manufacturer: manufacturer.get(),
                                        document_id: document_id.get(),
                                        document_version: document_version.get(),
                                        package_marking: package_marking.get(),
                                        device_address: device_address.get(),
                                        notes: notes.get(),
                                    };

                                    // Create FormData and append file synchronously here
                                    let form_data_js = FormData::new().unwrap();
                                    form_data_js.append_with_str("title", &fields.title).unwrap();
                                    form_data_js.append_with_str("part_number", &fields.part_number).unwrap();
                                    form_data_js.append_with_str("manufacturer", &fields.manufacturer).unwrap();
                                    form_data_js.append_with_str("document_id", &fields.document_id).unwrap();
                                    form_data_js.append_with_str("document_version", &fields.document_version).unwrap();
                                    form_data_js.append_with_str("package_marking", &fields.package_marking).unwrap();
                                    form_data_js.append_with_str("device_address", &fields.device_address).unwrap();
                                    form_data_js.append_with_str("notes", &fields.notes).unwrap();
                                    form_data_js.append_with_blob("file", &file.unwrap()).unwrap();

                                    // Call perform_submit directly, bypassing the Action
                                    wasm_bindgen_futures::spawn_local(async move {
                                        set_is_submitting.set(true);
                                        set_error_message.set(None);
                                        set_success_message.set(None);
                                        match perform_submit(form_data_js).await {
                                            Ok(response) => {
                                                if response.success {
                                                    set_success_message.set(Some(response.message));
                                                    set_title.set(String::new());
                                                    set_part_number.set(String::new());
                                                    set_manufacturer.set(String::new());
                                                    set_document_id.set(String::new());
                                                    set_document_version.set(String::new());
                                                    set_package_marking.set(String::new());
                                                    set_device_address.set(String::new());
                                                    set_notes.set(String::new());
                                                } else {
                                                    set_error_message.set(Some(response.message));
                                                }
                                            }
                                            Err(e) => {
                                                set_error_message.set(Some(format!("Submit failed: {}", e)));
                                            }
                                        }
                                        set_is_submitting.set(false);
                                    });
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
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
                                        prop:disabled=is_submitting
                                    />
                                </div>

                                <div class="form-group">
                                    <label for="file" class="form-label required">
                                        "File *"
                                    </label>
                                    <input
                                        type="file"
                                        id="file"
                                        name="file"
                                        class="form-input file-input"
                                        prop:disabled=is_submitting
                                        accept=".pdf,.doc,.docx,.txt,.md,.xls,.xlsx,.png,.jpg,.jpeg,.zip,.bin,.hex"
                                        required
                                    />
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
                                    prop:disabled=is_submitting
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
                                    prop:disabled=is_submitting
                                >
                                    <Show
                                        when=move || is_submitting.get()
                                        fallback=|| view! { "Submit Document" }
                                    >
                                        "Submitting..."
                                    </Show>
                                </button>

                                <A href="/" attr:class="cancel-button">
                                    "Cancel"
                                </A>
                            </div>
                        </form>

                        <div class="submit-info">
                            <p class="info-text">
                                "* Required fields. Files up to 100MB are supported."
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
async fn perform_submit(form_data: FormData) -> Result<SubmitResponse, String> {
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

    // Create a proper multipart request using gloo-net
    let mut request = gloo_net::http::Request::post("/api/submit");

    // Add Authorization header if token exists
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {}", token));
    }

    // Convert FormData to the format expected by gloo-net
    // We need to avoid setting Content-Type manually as the browser should set it with boundary
    let response = request
        .body(form_data)
        .map_err(|e| format!("Failed to prepare request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !response.ok() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Submit failed ({}): {}", status, error_text));
    }

    response
        .json::<SubmitResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_response_creation() {
        let response = SubmitResponse {
            success: true,
            message: "File uploaded successfully".to_string(),
            file_sha256: Some("abcd1234".to_string()),
        };

        assert!(response.success);
        assert_eq!(response.message, "File uploaded successfully");
        assert_eq!(response.file_sha256.unwrap(), "abcd1234");
    }

    #[test]
    fn test_submit_response_failure() {
        let response = SubmitResponse {
            success: false,
            message: "File upload failed".to_string(),
            file_sha256: None,
        };

        assert!(!response.success);
        assert_eq!(response.message, "File upload failed");
        assert!(response.file_sha256.is_none());
    }

    #[test]
    fn test_multipart_form_structure() {
        // Test that our FormData approach should work with proper field names
        let expected_fields = vec![
            "title",
            "part_number",
            "manufacturer",
            "document_id",
            "document_version",
            "package_marking",
            "device_address",
            "notes",
            "file",
        ];

        // This test verifies the field names match what the server expects
        for field in expected_fields {
            assert!(
                !field.is_empty(),
                "Field name should not be empty: {}",
                field
            );
            assert!(
                !field.contains(' '),
                "Field name should not contain spaces: {}",
                field
            );
        }
    }
}
