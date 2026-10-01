use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn Footer() -> impl IntoView {
    view! {
        <footer class="app-footer">
            <div class="footer-content">
                <nav class="footer-nav">
                    <A href="/all" attr:class="footer-link">
                        "All Files"
                    </A>
                </nav>
                <a href="https://ralimtek.com" target="_blank" class="footer-link">
                    "Made in annoyance by Ralim"
                </a>
            </div>
        </footer>
    }
}
