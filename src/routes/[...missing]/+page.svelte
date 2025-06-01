
<script>
    import { onMount } from "svelte";
    import { goto } from "$app/navigation";
    import {invoke} from "@tauri-apps/api/core";

    onMount(async () => {
        try {
            const session = await invoke("tauri_get_session");

            if (session.role === "admin") {
                goto("/admin");
            } else if (session.role === "user") {
                goto("/user");
            }
        } catch {}
    });
</script>

<div class="flex items-center justify-center h-screen">
    <span class="loading loading-spinner text-primary"></span>
</div>
