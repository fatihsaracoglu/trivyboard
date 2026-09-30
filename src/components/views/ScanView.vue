<script setup lang="ts">
import { ref, defineAsyncComponent } from "vue";
import { Boxes, HardDrive, GitBranch } from "@lucide/vue";
import Tabs from "@/components/ui/Tabs.vue";
import TabsList from "@/components/ui/TabsList.vue";
import TabsTrigger from "@/components/ui/TabsTrigger.vue";
import TabsContent from "@/components/ui/TabsContent.vue";

const DockerImagesTab = defineAsyncComponent(
  () => import("@/components/scan/DockerImagesTab.vue"),
);
const FilesystemTab = defineAsyncComponent(
  () => import("@/components/scan/FilesystemTab.vue"),
);
const RepositoryTab = defineAsyncComponent(
  () => import("@/components/scan/RepositoryTab.vue"),
);

const activeTab = ref<"image" | "fs" | "repo">("image");
</script>

<template>
  <div class="mx-auto max-w-5xl px-4 py-6 sm:px-6 lg:px-8">
    <Tabs v-model="activeTab" class="mb-6">
      <TabsList class="grid w-full grid-cols-3">
        <TabsTrigger value="image">
          <Boxes class="h-4 w-4" />
          Docker Image
        </TabsTrigger>
        <TabsTrigger value="fs">
          <HardDrive class="h-4 w-4" />
          Filesystem
        </TabsTrigger>
        <TabsTrigger value="repo">
          <GitBranch class="h-4 w-4" />
          Repository
        </TabsTrigger>
      </TabsList>

      <TabsContent value="image">
        <DockerImagesTab />
      </TabsContent>
      <TabsContent value="fs">
        <FilesystemTab />
      </TabsContent>
      <TabsContent value="repo">
        <RepositoryTab />
      </TabsContent>
    </Tabs>
  </div>
</template>
