<script setup lang="ts">
import { useRouter } from "vue-router";
import { Compass, ArrowLeft } from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import { Card } from "@/components/ui/card";

const router = useRouter();

function goHome() {
  router.push({ name: "upload" });
}
</script>

<template>
  <div class="mx-auto flex min-h-[60vh] max-w-md items-center justify-center px-4 py-12">
    <Card class="w-full overflow-hidden">
      <div class="flex flex-col items-center justify-center px-6 py-14 text-center">
        <div class="mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Compass class="h-7 w-7" />
        </div>
        <div class="mb-1 font-mono text-4xl font-semibold tabular-nums text-foreground">404</div>
        <h1 class="text-lg font-medium text-foreground">Page not found</h1>
        <p class="mt-1 text-sm text-muted-foreground">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <Button class="mt-6" size="default" @click="goHome">
          <ArrowLeft class="h-4 w-4" />
          Back to upload
        </Button>
      </div>
    </Card>
  </div>
</template>
