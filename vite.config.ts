import { defineConfig, loadEnv } from "vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";

const srcDir = fileURLToPath(new URL("./src", import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  const apiProxyTarget =
      env.API_PROXY_TARGET || "http://127.0.0.1:3030";

  const proxyUrl = new URL(apiProxyTarget);

  if (!["http:", "https:"].includes(proxyUrl.protocol)) {
    throw new Error(
        "API_PROXY_TARGET must use the http or https protocol",
    );
  }

  return {
    plugins: [vue()],

    resolve: {
      alias: {
        "@": srcDir,
      },
    },

    server: {
      port: 3000,
      host: "127.0.0.1",
      strictPort: true,
      proxy: {
        "/api": {
          target: apiProxyTarget,
          changeOrigin: true,
        },
      },
    },

    build: {
      sourcemap: false,
    },
  };
});