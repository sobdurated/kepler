// fetch running processes
async function fetchProcesses() {
    try {
        const apps = await window.__TAURI__.core.invoke("get_running_apps");
        console.log("running apps", apps);
    } catch (err) {
        console.error(err);
    }
}
document.addEventListener("DOMContentLoaded", fetchProcesses);
