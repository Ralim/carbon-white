// Signal setters are only ever mutated from `hydrate`-gated effects and event
// handlers, so they read as unused in an SSR-only build.
#![cfg_attr(not(feature = "hydrate"), allow(unused_variables))]

use crate::{components::header::Header, pages::footer::Footer};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

/// One page of documents returned by `GET /api/documents`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub results: Vec<SearchResult>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
    pub has_previous: bool,
    pub has_next: bool,
    pub duration_ms: u128,
}

/// Row shape shared with the search listing so both tables stay in step.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub part_number: String,
    pub manufacturer: String,
    pub document_id: String,
    pub document_version: String,
    pub package_marking: String,
    pub device_address: String,
    pub notes: String,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
}

/// Page listing every uploaded document, 100 per page.
#[component]
pub fn AllFilesPage() -> impl IntoView {
    let (page, set_page) = signal(1i64);
    let (total_pages, set_total_pages) = signal(1i64);
    let (documents, set_documents) = signal(Vec::<SearchResult>::new());
    let (is_loading, set_is_loading) = signal(false);
    let (error_message, set_error_message) = signal(Option::<String>::None);
    let (is_authenticated, _set_is_authenticated) = signal(false);

    // Reload the listing whenever the requested page changes.
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        use leptos::task::spawn_local;

        let requested_page = page.get();
        set_is_loading.set(true);
        set_error_message.set(None);

        spawn_local(async move {
            let token = stored_auth_token();

            let mut auth_request = gloo_net::http::Request::get("/api/auth/status");
            if let Some(token) = token.as_ref() {
                auth_request = auth_request.header("Authorization", &format!("Bearer {}", token));
            }

            // A failure here only hides the "Edit" actions; the listing itself
            // is public, so do not surface it as a page-level error.
            if let Some(authenticated) = fetch_auth_status(auth_request).await {
                _set_is_authenticated.set(authenticated);
            }

            match fetch_page(requested_page).await {
                Ok(response) => {
                    set_documents.set(response.results);
                    set_total_pages.set(response.total_pages);
                    // The server clamps out-of-range pages, so follow it.
                    if response.page != requested_page {
                        set_page.set(response.page);
                    }
                }
                Err(e) => {
                    set_error_message.set(Some(e));
                    set_documents.set(Vec::new());
                    set_total_pages.set(1);
                }
            }

            set_is_loading.set(false);
        });
    });

    view! {
        <div class="app-container">
            <Header is_authenticated/>

            <div class="main-content">
                <Show
                    when=move || error_message.get().is_some()
                    fallback=|| view! { <div></div> }
                >
                    <div class="error-message">
                        {move || error_message.get().unwrap_or_default()}
                    </div>
                </Show>

                <Show
                    when=move || !documents.get().is_empty()
                    fallback=move || {
                        let message = if is_loading.get() {
                            "Loading...".to_string()
                        } else {
                            "No documents have been uploaded yet.".to_string()
                        };
                        view! { <div class="all-files-empty">{message}</div> }
                    }
                >
                    <div class="results-container">
                        <table class="results-table">
                            <thead>
                                <tr>
                                    <th>"Title"</th>
                                    <th>"Part Number"</th>
                                    <th>"Manufacturer"</th>
                                    <th>"Document ID"</th>
                                    <th>"Version"</th>
                                    <th>"Package Marking"</th>
                                    <th>"Device Address"</th>
                                    <th>"Notes"</th>
                                    <th>"Storage Date"</th>
                                    <th>"Actions"</th>
                                </tr>
                            </thead>
                            <tbody>
                                <For
                                    each=move || documents.get()
                                    key=|doc| doc.file_sha256.clone()
                                    children=move |doc| {
                                        view! {
                                            <DocumentRow document=doc is_authenticated/>
                                        }
                                    }
                                />
                            </tbody>
                        </table>
                    </div>

                    <Pagination page=page total_pages=total_pages set_page=set_page />
                </Show>
            </div>

            <Footer/>
        </div>
    }
}

/// A single row in the all-files table.
#[component]
fn DocumentRow(document: SearchResult, is_authenticated: ReadSignal<bool>) -> impl IntoView {
    let download_url = format!("/file/{}", document.file_sha256);
    let edit_url = format!("/edit/{}", document.file_sha256);

    view! {
        <tr class="result-row">
            <td class="result-title">{document.title}</td>
            <td class="result-part-number">{document.part_number}</td>
            <td class="result-manufacturer">{document.manufacturer}</td>
            <td class="result-document-id">{document.document_id}</td>
            <td class="result-version">{document.document_version}</td>
            <td class="result-package-marking">{document.package_marking}</td>
            <td class="result-device-address">{document.device_address}</td>
            <td><div class="result-notes">{document.notes}</div></td>
            <td class="result-storage-date">{document.storage_date}</td>
            <td class="result-actions">
                <a href=download_url class="download-button" target="_blank">
                    "View"
                </a>
                <Show
                    when=move || is_authenticated.get()
                    fallback=|| view! { <div></div> }
                >
                    <a href=edit_url.clone() class="edit-button">
                        "Edit"
                    </a>
                </Show>
            </td>
        </tr>
    }
}

/// Previous/next pager. Only renders when there is more than one page, so an
/// empty or single-page listing shows no pager at all.
///
/// Uses plain buttons: these drive a signal rather than navigating, so a link
/// would be misleading about what clicking it does.
#[component]
fn Pagination(
    page: ReadSignal<i64>,
    total_pages: ReadSignal<i64>,
    set_page: WriteSignal<i64>,
) -> impl IntoView {
    let previous_disabled = Signal::derive(move || page.get() <= 1);
    let next_disabled = Signal::derive(move || page.get() >= total_pages.get());

    let go_previous = move |_| {
        let current = page.get();
        if current > 1 {
            set_page.set(current - 1);
        }
    };

    let go_next = move |_| {
        let current = page.get();
        if current < total_pages.get() {
            set_page.set(current + 1);
        }
    };

    let show_pager = move || total_pages.get() > 1;

    view! {
        <Show when=show_pager fallback=|| view! { <div></div> }>
            <nav class="pagination" aria-label="Pagination">
                <button
                    type="button"
                    class="pagination-button"
                    prop:disabled=move || previous_disabled.get()
                    on:click=go_previous
                >
                    "Previous"
                </button>

                <span class="pagination-status">
                    {move || format!("Page {} of {}", page.get(), total_pages.get())}
                </span>

                <button
                    type="button"
                    class="pagination-button"
                    prop:disabled=move || next_disabled.get()
                    on:click=go_next
                >
                    "Next"
                </button>
            </nav>
        </Show>
    }
}

/// Asks the server whether the supplied request carries a valid session.
///
/// Returns `None` on any build, transport or decoding failure, so callers can
/// treat an unknown auth state as "not authenticated" without branching on
/// errors.
#[cfg(feature = "hydrate")]
async fn fetch_auth_status(request: gloo_net::http::RequestBuilder) -> Option<bool> {
    use crate::shared::AuthStatusResponse;

    let response = request.build().ok()?.send().await.ok()?;
    let status = response.json::<AuthStatusResponse>().await.ok()?;
    Some(status.authenticated)
}

/// Reads the auth token from `localStorage`.
#[cfg(feature = "hydrate")]
fn stored_auth_token() -> Option<String> {
    web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item("carbon_auth_token").ok().flatten())
}

/// Fetches one page from the server-side listing endpoint.
#[cfg(feature = "hydrate")]
async fn fetch_page(page: i64) -> Result<ListResponse, String> {
    let response = gloo_net::http::Request::get(&format!("/api/documents?page={}", page))
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if !response.ok() {
        return Err(format!("Failed to load documents: {}", response.status()));
    }

    response
        .json::<ListResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc(index: usize) -> SearchResult {
        SearchResult {
            title: format!("Document {}", index),
            part_number: format!("PN{:03}", index),
            manufacturer: "Test Corp".to_string(),
            document_id: format!("DOC{:03}", index),
            document_version: "1.0".to_string(),
            package_marking: "QFN32".to_string(),
            device_address: "0x48".to_string(),
            notes: String::new(),
            storage_date: "2024-01-01".to_string(),
            original_file_name: format!("doc{}.pdf", index),
            file_sha256: format!("{:064x}", index),
        }
    }

    #[test]
    fn test_list_response_creation() {
        let response = ListResponse {
            results: vec![sample_doc(1), sample_doc(2)],
            page: 1,
            per_page: 100,
            total: 2,
            total_pages: 1,
            has_previous: false,
            has_next: false,
            duration_ms: 5,
        };

        assert_eq!(response.results.len(), 2);
        assert_eq!(response.page, 1);
        assert!(!response.has_next);
        assert_eq!(response.total, 2);
    }

    #[test]
    fn test_list_response_deserializes_from_server_json() {
        // Mirrors the JSON emitted by `handle_list` so a change to the
        // wire format fails here rather than silently in the browser.
        let raw = r#"{
            "results": [{
                "title": "D",
                "part_number": "P",
                "manufacturer": "M",
                "document_id": "I",
                "document_version": "1.0",
                "package_marking": "Q",
                "device_address": "0x0",
                "notes": "n",
                "storage_date": "2024-01-01",
                "original_file_name": "d.pdf",
                "file_sha256": "abc"
            }],
            "page": 2,
            "per_page": 100,
            "total": 150,
            "total_pages": 2,
            "has_previous": true,
            "has_next": false,
            "duration_ms": 3
        }"#;

        let response: ListResponse = serde_json::from_str(raw).unwrap();

        assert_eq!(response.page, 2);
        assert_eq!(response.total, 150);
        assert_eq!(response.total_pages, 2);
        assert!(response.has_previous);
        assert!(!response.has_next);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].title, "D");
    }
}
