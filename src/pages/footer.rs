use leptos::prelude::*;

#[component]
pub fn Footer() -> impl IntoView {
    view! {
        <footer class="app-footer">
            <div class="footer-content">
                <a href="https://ralimtek.com" target="_blank" class="footer-link">
                    "Made in annoyance by Ralim"
                </a>
            </div>
        </footer>
    }
}
