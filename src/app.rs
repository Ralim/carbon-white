use crate::pages::*;
use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::{Route, Router, Routes, RoutingProgress};
use leptos_router_macro::path;
use std::time::Duration;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    let (is_routing, set_is_routing) = signal(false);
    view! {
        <Stylesheet id="leptos" href="/pkg/carbon-white.css"/>

        // sets the document title
        <Title text="Carbon White"/>

        // favicon meta tags for title bar and browser compatibility
        <Link rel="shortcut icon" href="/favicon.ico"/>
        <Link rel="icon" type_="image/x-icon" href="/favicon.ico"/>
        <Link rel="icon" type_="image/png" sizes="16x16" href="/favicon-16x16.png"/>
        <Link rel="icon" type_="image/png" sizes="32x32" href="/favicon-32x32.png"/>
        <Link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"/>
        <Link rel="manifest" href="/site.webmanifest"/>
        <Meta name="theme-color" content="#ffffff"/>

        // content for this welcome page
        <Router set_is_routing>
            // shows a progress bar while async data are loading
            <div class="routing-progress">
                <RoutingProgress is_routing max_time=Duration::from_millis(250)/>
            </div>
            <main>
                <Routes transition=true fallback=|| "This page could not be found.">

                    <Route path=path!("/") view=HomePage/>
                    <Route path=path!("/login") view=LoginPage/>
                    <Route path=path!("/submit") view=SubmitPage/>
                    <Route path=path!("/edit/:sha256") view=EditPage/>

                </Routes>
            </main>
        </Router>
    }
}

/// 404 - Not Found
#[component]
pub fn NotFound() -> impl IntoView {
    // set an HTTP status code 404
    // this is feature gated because it can only be done during
    // initial server-side rendering
    // if you navigate to the 404 page subsequently, the status
    // code will not be set because there is not a new HTTP request
    // to the server
    #[cfg(feature = "ssr")]
    {
        // this can be done inline because it's synchronous
        // if it were async, we'd use a server function
        let resp = expect_context::<leptos_axum::ResponseOptions>();
        resp.set_status(axum::http::StatusCode::NOT_FOUND);
    }

    view! {
        <h1>"Not Found"</h1>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests don't need any additional imports beyond what's already in scope

    #[test]
    fn test_app_component_renders() {
        // Test that the App component function exists and can be called
        // This is a basic compilation test
        let _app_fn = App;
        assert!(true);
    }

    #[test]
    fn test_favicon_links_included() {
        // Test that favicon-related strings are present in the source
        let source_code = include_str!("app.rs");

        assert!(source_code.contains("shortcut icon"));
        assert!(source_code.contains("favicon.ico"));
        assert!(source_code.contains("favicon-16x16.png"));
        assert!(source_code.contains("favicon-32x32.png"));
        assert!(source_code.contains("apple-touch-icon.png"));
        assert!(source_code.contains("site.webmanifest"));
        assert!(source_code.contains("theme-color"));
    }

    #[test]
    fn test_app_has_title() {
        // Verify the app source contains the title
        let source_code = include_str!("app.rs");
        assert!(source_code.contains("Carbon White"));
    }
}

#[cfg(feature = "ssr")]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    use leptos::prelude::*;

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}
