<script>
    import { onMount } from 'svelte';
    import { invoke } from "@tauri-apps/api/core";
    import { message, ask } from '@tauri-apps/plugin-dialog';

    let users = [];
    let loading = true;
    let errorMsg = '';
    let currentUsername = '';

    let editDialog;
    let userId = '';
    let originalUsername = '';
    let formUsername = '';
    let formPassword = '';
    let formBlocked = false;
    let formMinLength = '';

    let formError = '';

    let addDialog;
    let newUsername = '';
    let addError = '';

    async function fetchUsers() {
        loading = true;
        errorMsg = '';
        try {
            users = await invoke('tauri_get_users');
        } catch (err) {
            errorMsg = typeof err === 'string' ? err : 'Failed to load users.';
        } finally {
            loading = false;
        }
    }

    onMount(async () => {
        try {
            const session = await invoke('tauri_get_session');
            currentUsername = session.sub;

            users = await invoke('tauri_get_users');
        } catch (err) {
            errorMsg = String(err);
        } finally {
            loading = false;
        }
    });

    function openEditDialog(user) {
        userId = user.id;
        originalUsername = user.username;
        formUsername = user.username;
        formPassword = '';
        formBlocked = user.blocked;
        formMinLength = user.min_password_length !== null ? String(user.min_password_length) : '';
        formError = '';
        editDialog.showModal();
    }

    function closeEditDialog() {
        formError = '';
        editDialog.close();
    }

    async function saveChanges(event) {
        event.preventDefault();
        formError = '';

        if (!formUsername.trim()) {
            formError = 'Username cannot be empty.';
            return;
        }

        let minLenValue = null;
        if (String(formMinLength).trim() !== '') {
            const parsed = parseInt(formMinLength);
            if (isNaN(parsed) || parsed < 1) {
                formError = 'Min length must be a positive integer or blank.';
                return;
            }
            minLenValue = parsed;
        }

        try {
            if (formUsername !== originalUsername) {
                await invoke('tauri_rename_user', {
                    oldUsername: originalUsername,
                    newUsername: formUsername
                });
            }

            if (formPassword.trim() !== '') {
                const success = await invoke('tauri_override_password', {
                    userId: userId,
                    newPassword: formPassword
                });
                if (!success) {
                    formError = 'Password did not meet requirements or wrong.';
                    return;
                }
            }

            await invoke('tauri_set_block_status', {
                userId: userId,
                block: formBlocked
            });

            await invoke('tauri_set_restriction', {
                userId: userId,
                minLength: minLenValue
            });

            await fetchUsers();
            editDialog.close();
        } catch (e) {
            await message(`Failed to save changes: ${String(e)}`, {
                title: 'Error',
                kind: 'error'
            });
        }
    }

    function openAddDialog() {
        newUsername = '';
        addError = '';
        addDialog.showModal();
    }

    function closeAddDialog() {
        addError = '';
        addDialog.close();
    }

    async function createUser(event) {
        event.preventDefault();
        addError = '';

        if (!newUsername.trim()) {
            addError = 'Username cannot be empty.';
            return;
        }

        try {
            const created = await invoke('tauri_add_user', { username: newUsername.trim() });
            if (!created) {
                addError = 'User already exists.';
                return;
            }
            await fetchUsers();
            addDialog.close();
        } catch (e) {
            await message(`Failed to add user: ${String(e)}`, {
                title: 'Error',
                kind: 'error'
            });
        }
    }

    async function deleteUser(user) {
        const confirmed  = await ask(
            `Are you sure you want to delete ${user.username}?`,
            {title: 'warning', kind: 'warning'},
        );

        if (!confirmed) return;

        try {
            await invoke("tauri_delete_user", { userId: user.id });
            await fetchUsers();
        } catch (e) {
            await message(`Failed to delete user: ${String(e)}`, {title: 'Error', kind: 'error'});
        }
    }

</script>

{#if loading}
    <div class="flex items-center justify-center h-screen">
        <span class="loading loading-spinner text-primary"></span>
    </div>
{:else if errorMsg}
    <div class="p-6">
        <div class="alert alert-error">
            <span>{errorMsg}</span>
        </div>
    </div>
{:else}
    <div class="p-6">
        <div class="breadcrumbs text-sm">
            <ul>
                <li><a href="/admin">Home</a></li>
                <li>User list</li>
            </ul>
        </div>
        <div class="flex justify-between items-center mb-4">
            <h1 class="text-2xl font-semibold mb-4">User List</h1>
            <button class="btn btn-primary btn-sm" on:click={openAddDialog}>Add user</button>
        </div>
        <div class="overflow-x-auto">
            <table class="table table-zebra w-full">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Restricted Length</th>
                    <th></th>
                </tr>
                </thead>
                <tbody>
                {#each users as user}
                    <tr>
                        <td>{user.id}</td>
                        <td>{user.username}</td>
                        <td>{user.role}</td>
                        <td>
                            {#if user.blocked}
                                <span class="badge badge-soft badge-error">Blocked</span>
                            {:else}
                                <span class="badge badge-soft badge-success">Active</span>
                            {/if}
                        </td>
                        <td>
                            {#if user.min_password_length !== null}
                                <span class="badge badge-soft badge-info">{user.min_password_length}</span>
                            {:else}
                                <span class="badge badge-soft">None</span>
                            {/if}
                        </td>
                        <td>
                            {#if user.username !== currentUsername}
                            <button class="btn btn-sm btn-soft btn-error" on:click={() => deleteUser(user)}>
                                Delete
                            </button>
                            <button class="btn btn-sm btn-soft" on:click={() => openEditDialog(user)}>
                                Edit
                            </button>
                            {/if}
                        </td>
                    </tr>
                {/each}
                </tbody>
            </table>
        </div>
    </div>
{/if}

<dialog bind:this={editDialog} class="modal">
    <form method="dialog" class="modal-box" on:submit|preventDefault={saveChanges}>
        <h3 class="font-bold text-lg mb-4">Edit User: {originalUsername} (ID: {userId})</h3>

        <fieldset class="fieldset">
            <legend class="fieldset-legend">Username</legend>
            <input
                    type="text"
                    class="input input-sm w-full"
                    bind:value={formUsername}
                    autocomplete="off"
                    disabled
            />
        </fieldset>

        <fieldset class="fieldset">
            <legend class="fieldset-legend">Password</legend>
            <input
                    type="password"
                    class="input input-sm w-full"
                    bind:value={formPassword}
                    placeholder="Enter new password"
                    autocomplete="off"
            />
        </fieldset>

        <fieldset class="fieldset">
            <legend class="fieldset-legend">Min password length</legend>
            <input
                    type="number"
                    class="input input-sm w-full"
                    min="1"
                    bind:value={formMinLength}
            />
        </fieldset>

        <fieldset class="fieldset">
            <legend class="fieldset-legend">Login settings</legend>
            <label class="label">
                <input
                        type="checkbox"
                        bind:checked={formBlocked}
                        class="toggle toggle-error"
                />
                Is blocked?
            </label>
        </fieldset>


        {#if formError}
            <div class="text-sm text-red-600 mb-2">{formError}</div>
        {/if}

        <div class="modal-action">
            <button type="button" class="btn" on:click={closeEditDialog}>Cancel</button>
            <button type="submit" class="btn btn-primary">Save</button>
        </div>
    </form>
</dialog>

<dialog bind:this={addDialog} class="modal">
    <form method="dialog" class="modal-box" on:submit|preventDefault={createUser}>
        <h3 class="font-bold text-lg mb-4">Add new user</h3>


        <fieldset class="fieldset">
            <legend class="fieldset-legend">Username</legend>
            <input
                    type="text"
                    class="input input-sm w-full"
                    bind:value={newUsername}
                    placeholder="Enter new username"
                    autocomplete="off"
                    required
            />
            <p class="label">The password will be set to NULL and the user will be prompted to enter it</p>
        </fieldset>


        {#if addError}
            <div class="text-sm text-red-600 mb-2">{addError}</div>
        {/if}

        <div class="modal-action">
            <button type="button" class="btn btn-soft" on:click={closeAddDialog}>Cancel</button>
            <button type="submit" class="btn btn-primary">Create</button>
        </div>
    </form>
</dialog>