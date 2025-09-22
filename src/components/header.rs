use leptos::prelude::*;
use leptos_router::components::A;

/// Header component that displays "Submit" if authenticated, "Login" otherwise.
/// Expects a `ReadSignal<bool>` indicating authentication state.
#[component]
pub fn Header(is_authenticated: ReadSignal<bool>) -> impl IntoView {
    view! {
        <header class="app-header">
            <div class="header-content">
                <A href="/">
                    <h1 class="app-title">"Carbon White"</h1>
                </A>
                <div class="header-actions">
                    <Show
                        when=move || is_authenticated.get()
                        fallback=|| view! {
                            <A href="/login" attr:class="header-button">
                                "Login"
                            </A>
                        }
                    >
                        // Show Logout and Submit when authenticated
                        <div style="display: flex; gap: 0.5rem;">
                            <button
                                class="header-button"
                                on:click=move |_| {
                                    // Remove token from localStorage and reload
                                    #[cfg(feature = "hydrate")]
                                    {
                                        if let Some(window) = web_sys::window() {
                                            if let Some(storage) = window.local_storage().unwrap_or(None) {
                                                let _ = storage.remove_item("carbon_auth_token");
                                            }
                                            window.location().set_href("/").ok();
                                        }
                                    }
                                }
                                type="button"
                            >
                                "Logout"
                            </button>
                            <A href="/submit" attr:class="header-button">
                                "Submit"
                            </A>
                        </div>
                    </Show>
                </div>
            </div>
        </header>
    }
}
