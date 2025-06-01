<script>
    import { onMount } from 'svelte';
    import { invoke } from "@tauri-apps/api/core";
    import { goto } from '$app/navigation';

    let userName = '';
    let loading = true;
    let logoutError = '';

    onMount(async () => {
        try {
            const session =
                await invoke('tauri_get_session');
            userName = session.sub;
        } catch {
            goto('/');
        } finally {
            loading = false;
        }
    });

    function goToUserList() {
        goto('/admin/users');
    }

    function goToChangePassword() {
        goto('/passwd');
    }

    async function handleLogout() {
        logoutError = '';
        try {
            await invoke('tauri_logout');
            goto('/');
        } catch (err) {
            logoutError = String(err);
        }
    }
</script>

{#if loading}
    <div class="flex items-center justify-center h-screen">
        <span class="loading loading-spinner text-primary"></span>
    </div>
{:else}
    <div class="p-6 w-full">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div
                    class="card bg-base-300 shadow hover:bg-neutral cursor-pointer transition"
                    on:click={goToUserList}
            >
                <div class="card-body text-left">
                    <h3 class="card-title">User List</h3>
                    <p>View and manage all registered users</p>
                </div>
            </div>

            <div
                    class="card bg-base-300 shadow hover:bg-neutral cursor-pointer transition"
                    on:click={goToChangePassword}
            >
                <div class="card-body text-left">
                    <h3 class="card-title">Change Password</h3>
                    <p>Update your password</p>
                </div>
            </div>

        </div>
    </div>
{/if}
