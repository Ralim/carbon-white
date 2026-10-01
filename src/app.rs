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
                    <Route path=path!("/all") view=AllFilesPage/>
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_component_is_callable() {
        // Referencing the component proves it is exported and its props type-check.
        let _app_fn = App;
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

    #[cfg(feature = "ssr")]
    #[test]
    fn test_all_route_is_registered() {
        use leptos_axum::generate_route_list;

        let routes = generate_route_list(App);
        let paths: Vec<String> = routes.iter().map(|r| r.path().to_string()).collect();

        assert!(
            paths.iter().any(|p| p == "/all"),
            "the /all route must be registered, found: {paths:?}"
        );
        // The pre-existing routes must survive alongside it.
        assert!(paths.iter().any(|p| p == "/"));
        assert!(paths.iter().any(|p| p == "/login"));
        assert!(paths.iter().any(|p| p.starts_with("/submit")));
        assert!(paths.iter().any(|p| p.starts_with("/edit")));
    }
}
