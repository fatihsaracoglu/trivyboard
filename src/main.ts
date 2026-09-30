import { createApp } from "vue";
import { createPinia } from "pinia";
import App from "./App.vue";
import { router } from "./router";
import { initTheme } from "./composables/useTheme";
import "./globals.css";

const app = createApp(App);

app.config.errorHandler = (err, _instance, info) => {
  console.error("[Vue error]", info, err);
};

app.use(createPinia());
app.use(router);

initTheme();

app.mount("#app");
