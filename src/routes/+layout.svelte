<script>
    import Navbar from "$lib/components/Navbar.svelte";
    import "../app.css";

    import { onMount } from 'svelte';
    import { invoke } from "@tauri-apps/api/core";
    import { goto } from '$app/navigation';
    import { page } from "$app/state";

    let name = "";
    let role = "";

    onMount(async () => {
        try {
            const session = await invoke("tauri_get_session");
            name = session.sub;
            role = session.role;

            if (page.url.pathname === "/") {
                goto(role === "admin" ? "/admin" : "/user");
            }
        } catch {
            if (page.url.pathname !== "/") {
                goto("/");
            }
        }

    });
</script>

{#if page.url.pathname !== "/"}
    <Navbar />
{/if}

<slot/>
