<script>
    import {onMount} from "svelte";
    import {invoke} from "@tauri-apps/api/core";
    import { goto } from '$app/navigation';

    let userId = null;
    let minPasswordLength = null;
    let currentPassword = "";
    let newPassword = "";
    let errorMessage = "";
    let successMessage = "";
    let loading = true;
    let role = '';
    let username = '';

    onMount(async () => {
        try {

            const session = await invoke("tauri_get_session");
            username = session.sub;
            role = session.role;

            const user = await invoke("tauri_get_own_info");
            userId = user.id;
            minPasswordLength = user.min_password_length;
            
        } catch (e) {
            errorMessage = "Unable to determine user ID. " + String(e);
        } finally {
            loading = false;
        }
    });

    function goHome() {
        goto(role === "admin" ? "/admin" : "/user");
    }

    async function handleSubmit() {
        errorMessage = "";
        successMessage = "";

        if (!currentPassword || !newPassword) {
            errorMessage = "Both fields are required.";
            return;
        }

        if (minPasswordLength !== null && newPassword.length < minPasswordLength) {
            errorMessage = `New password must be at least ${minPasswordLength} characters.`;
            return;
        }

        try {
            successMessage = await invoke("tauri_change_password", {
                userId,
                currentPassword,
                newPassword,
            });
            currentPassword = "";
            newPassword = "";
        } catch (e) {
            errorMessage = String(e);
        }
    }
</script>

{#if loading}
    <div class="flex items-center justify-center h-screen">
        <span class="loading loading-spinner text-primary"></span>
    </div>
{:else}
    <div class="p-6">
        <div class="breadcrumbs text-sm">
            <ul>
                <li><a on:click={goHome}>Home</a></li>
                <li>Account settings</li>
            </ul>
        </div>
        <div class="flex justify-between items-center mb-4">
            <h1 class="text-2xl font-semibold mb-4">Account settings</h1>
        </div>
        <div class="flex items-center justify-center">
            <div class="card w-96 bg-base-200">
                <div class="card-body">
                    <h2 class="card-title mb-6">Change Password</h2>

                    {#if errorMessage}
                        <div class="alert alert-soft alert-error">
                            <span>{errorMessage}</span>
                        </div>
                    {/if}

                    {#if successMessage}
                        <div class="alert alert-soft alert-success">
                            <span>{successMessage}</span>
                        </div>
                    {/if}

                    <fieldset class="fieldset">
                        <legend class="fieldset-legend">Current Password</legend>
                        <input
                                type="password"
                                class="input input-sm w-full"
                                bind:value={currentPassword}
                                placeholder="Enter current password"
                                autocomplete="off"
                        />
                    </fieldset>

                    <fieldset class="fieldset">
                        <legend class="fieldset-legend">New Password</legend>
                        <input
                                type="password"
                                class="input input-sm w-full"
                                bind:value={newPassword}
                                placeholder="Enter new password"
                                autocomplete="off"
                        />
                    </fieldset>

                    {#if minPasswordLength !== null}
                        <div class="flex flex-col items-start alert alert-soft alert-warning mb-4 mt-3">
                            <span class="font-medium">Password Restriction:</span>
                            <span>Your password must be at least <strong>{minPasswordLength}</strong> character(s)</span>
                        </div>
                    {/if}

                    <div class="form-control">
                        <button class="btn btn-md btn-primary" on:click={handleSubmit}>
                            Update Password
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

{/if}
