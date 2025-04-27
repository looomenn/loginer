<script>
  import { invoke } from "@tauri-apps/api/core";
  import { goto } from '$app/navigation';

  let username = $state("");
  let password = $state("");
  let errorMessage = $state("");

  async function login() {
    errorMessage = '';

    try {
      const role = await invoke("login", {username, password});
      if (role === 'admin') {
        goto('/admin');
      } else if (role === 'user') {
        goto('/user');
      } else {
        errorMessage = "Unknown role";
      }
    } catch (error) {
      errorMessage = String(error);
    }
  }
</script>

<main class="container">
  <h1>Loginer</h1>
  <form class="login-form" onsubmit={login}>
    <input class="input" type="text" placeholder="Username" required bind:value={username} />
    <input class="input" type="password" placeholder="Password" bind:value={password} />
    <button type="submit" class="btn w-64 rounded-full">Log in</button>
  </form>
  {#if errorMessage}
    <p style="color: red">{errorMessage}</p>
  {/if}
</main>

