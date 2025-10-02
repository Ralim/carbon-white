use crate::{components::header::Header, pages::footer::Footer};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub duration_ms: u128,
}

#[component]
pub fn HomePage() -> impl IntoView {
    let (search_term, set_search_term) = signal(String::new());
    let (search_results, set_search_results) = signal(Vec::<SearchResult>::new());
    let (is_searching, set_is_searching) = signal(false);
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

    // Load recent files on page load and perform search
    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        let term = search_term.get();

        set_is_searching.set(true);
        use leptos::task::spawn_local;
        spawn_local(async move {
            let result = if term.trim().is_empty() {
                // Load recent files when no search term
                perform_search("").await
            } else {
                // Perform actual search
                perform_search(&term).await
            };

            match result {
                Ok(response) => {
                    set_search_results.set(response.results);
                }
                Err(e) => {
                    leptos::logging::error!("Search/load error: {}", e);
                    set_search_results.set(Vec::new());
                }
            }
            set_is_searching.set(false);
        });
    });

    view! {
        <div class="app-container">
            <Header is_authenticated/>

            <div class="main-content">
                <div class="search-container">
                    <h1 class="search-title">"Search Documents"</h1>

                    <div class="search-box">
                        <input
                            type="text"
                            placeholder="Search for documents, part numbers, or manufacturers..."
                            class="search-input"
                            on:input=move |ev| {
                                set_search_term.set(event_target_value(&ev));
                            }
                            prop:value=search_term
                        />
                    </div>

                    <Show
                        when=move || is_searching.get()
                        fallback=|| view! { <div></div> }
                    >
                        <div class="search-loading">
                            "Searching..."
                        </div>
                    </Show>
                </div>

                <SearchResults results=search_results search_term=search_term is_authenticated=is_authenticated/>
            </div>

            <Footer/>
        </div>
    }
}

#[component]
fn SearchResults(
    results: ReadSignal<Vec<SearchResult>>,
    search_term: ReadSignal<String>,
    is_authenticated: ReadSignal<bool>,
) -> impl IntoView {
    let results_count = move || results.get().len();
    let is_search_empty = move || search_term.get().trim().is_empty();

    view! {
        <div class="search-results">
            <Show
                when=move || !results.get().is_empty()
                fallback=|| view! { <div></div> }
            >
                <div class="results-container">
                    <Show
                        when=is_search_empty
                        fallback=move || view! {
                            <h2 class="results-title">
                                {move || format!("Search Results ({})", results_count())}
                            </h2>
                        }
                    >
                        <h2 class="results-title">
                            {move || format!("Recent Files ({})", results_count())}
                        </h2>
                    </Show>

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
                                each=move || results.get()
                                key=|result| result.file_sha256.clone()
                                children=move |result| {
                                    view! {
                                        <SearchResultRow result is_authenticated/>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn SearchResultRow(result: SearchResult, is_authenticated: ReadSignal<bool>) -> impl IntoView {
    let download_url = format!("/file/{}", result.file_sha256);
    let edit_url = format!("/edit/{}", result.file_sha256);

    view! {
        <tr class="result-row">
            <td class="result-title">{result.title}</td>
            <td class="result-part-number">{result.part_number}</td>
            <td class="result-manufacturer">{result.manufacturer}</td>
            <td class="result-document-id">{result.document_id}</td>
            <td class="result-version">{result.document_version}</td>
            <td class="result-package-marking">{result.package_marking}</td>
            <td class="result-device-address">{result.device_address}</td>
            <td><div class="result-notes">{result.notes}</div></td>
            <td class="result-storage-date">{result.storage_date}</td>
            <td class="result-actions">
                <a href={download_url} class="download-button" target="_blank">
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

#[cfg(feature = "hydrate")]
async fn perform_search(query: &str) -> Result<SearchResponse, String> {
    let response =
        gloo_net::http::Request::get(&format!("/api/search?q={}", urlencoding::encode(query)))
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

    if !response.ok() {
        return Err(format!("Search failed with status: {}", response.status()));
    }

    response
        .json::<SearchResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_result_creation() {
        let result = SearchResult {
            title: "Test Document".to_string(),
            part_number: "PN123".to_string(),
            manufacturer: "Test Corp".to_string(),
            document_id: "DOC001".to_string(),
            document_version: "1.0".to_string(),
            package_marking: "QFN32".to_string(),
            device_address: "0x48".to_string(),
            notes: "Test notes".to_string(),
            storage_date: "2024-01-01".to_string(),
            original_file_name: "test.pdf".to_string(),
            file_sha256: "abcd1234".to_string(),
        };

        assert_eq!(result.title, "Test Document");
        assert_eq!(result.part_number, "PN123");
        assert_eq!(result.manufacturer, "Test Corp");
    }

    #[test]
    fn test_search_response_creation() {
        let response = SearchResponse {
            results: vec![],
            duration_ms: 50,
        };

        assert_eq!(response.results.len(), 0);
        assert_eq!(response.duration_ms, 50);
    }
}
