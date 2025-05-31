<script>
    import { invoke } from "@tauri-apps/api/core";
    import { goto } from "$app/navigation";

    let username = $state("");
    let password = $state("");
    let errorMessage = $state("");

    async function login() {
        errorMessage = "";

        try {
            const role = await invoke("tauri_login", { username, password });
            const session = await invoke("tauri_get_session");

            if (session.role === "admin") {
                goto("/admin");
            } else if (session.role === "user") {
                goto("/user");
            } else {
                errorMessage = "Unknown role";
            }
        } catch (error) {
            errorMessage = String(error);
        }
    }
</script>

<main>
    <div class="flex items-center justify-center min-h-screen bg-base-200">
        <div class="card w-96 bg-base-100 shadow-md">
            <div class="card-body">
                <h2 class="card-title justify-center mb-6">Login</h2>

                {#if errorMessage}
                    <div class="alert alert-error alert-soft mb-6">
                        <span>{errorMessage}</span>
                    </div>
                {/if}

                <form class="login-form" onsubmit={login}>
                    <div class="mb-6">
                        <label class="label" for="form_login_username">
                            <span class="label-text">Username</span>
                        </label>
                        <input
                            type="text"
                            bind:value={username}
                            placeholder="mr_parasyk"
                            class="input w-full mt-2 validator"
                            required
                            id="form_login_username"
                        />
                        <div class="validator-hint hidden">
                            Enter valid username
                        </div>
                    </div>
                    <div class="mb-8">
                        <label class="label" for="form_login_password">
                            <span class="label-text">Password</span>
                        </label>
                        <input
                            type="password"
                            bind:value={password}
                            placeholder="pass"
                            class="input w-full mt-2 validator"
                            required
                            id="form_login_password"
                        />
                        <div class="validator-hint hidden">Enter password</div>
                    </div>
                    <button type="submit" class="btn btn-primary w-full">
                        Login
                    </button>
                </form>
            </div>
        </div>
    </div>
</main>
