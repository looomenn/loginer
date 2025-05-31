<script>
    import { onMount } from 'svelte';
    import { invoke } from "@tauri-apps/api/core";
    import { goto } from '$app/navigation';
    import { message } from "@tauri-apps/plugin-dialog";

    let users = [];
    let loading = true;
    let errorMsg = '';

    async function fetchUsers(){
        loading = true;
        errorMsg = '';
        try {
            users = await invoke('tauri_get_users');
        } catch (error) {
            errorMsg = errorMsg;
        } finally {
            loading = false;
        }
    }

    onMount(fetchUsers);

    function editUser(username) {
        goto(`/admin/users/edit/${encodeURIComponent(username)}`);
    }

    async function toggleBlock(user){
        const newStatus = !user.blocked;
        try {
            await invoke('tauri_set_block_status', {
                username: user.username,
                block: newStatus
            })
        }
    }


</script>