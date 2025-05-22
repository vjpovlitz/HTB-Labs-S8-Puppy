# Managing Neo4j on Kali Linux (Recommended Method)

This guide explains how to install and manage Neo4j on Kali Linux using the official Neo4j APT repository, which provides proper systemd integration for reliable service management.

## Background

Previously, attempting to install Neo4j via `sudo apt install neo4j` using only the default Kali repositories resulted in an installation that lacked systemd integration, requiring manual management of the Neo4j process. This guide supersedes that manual method.

## Installation Steps (Neo4j 4.4.x Recommended for BloodHound)

Neo4j 4.4.x is generally recommended for compatibility with BloodHound. These steps install Neo4j 4.4.x:

1.  **Prerequisites (Install `curl` and `gpg` if not present):**
    ```bash
    sudo apt update
    sudo apt install -y curl gpg
    ```

2.  **Add Neo4j GPG Key and Repository:**
    This command sequence downloads the GPG key, stores it correctly for `apt`, adds the Neo4j 4.4 repository, updates package lists, and installs Neo4j:
    ```bash
    curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list \
    && sudo apt update \
    && sudo apt install -y neo4j
    ```

## Managing the Neo4j Service (systemd)

With this installation method, Neo4j is managed as a systemd service.

*   **Start Neo4j:**
    ```bash
    sudo systemctl start neo4j
    ```

*   **Stop Neo4j:**
    ```bash
    sudo systemctl stop neo4j
    ```

*   **Check Neo4j Status:**
    ```bash
    sudo systemctl status neo4j
    ```
    (Press `q` to exit the status view if it pages).

*   **Restart Neo4j:**
    ```bash
    sudo systemctl restart neo4j
    ```

*   **Enable Neo4j to Start on Boot:**
    ```bash
    sudo systemctl enable neo4j
    ```

*   **Disable Neo4j from Starting on Boot:**
    ```bash
    sudo systemctl disable neo4j
    ```

## Accessing Neo4j & Initial Setup

1.  **Ensure Neo4j is running:** `sudo systemctl status neo4j` (should show `active (running)`).
2.  **Open in Browser:** Navigate to `http://localhost:7474`.
3.  **Initial Login:** Connect with the default credentials:
    *   Username: `neo4j`
    *   Password: `neo4j`
4.  **Change Password:** You will be prompted to change the password immediately. Choose a new, strong password and **remember it**. This new password will be needed for BloodHound to connect to Neo4j.

## Important Notes

*   **Java Version Troubleshooting (Critical for Neo4j 4.4.x):**
    *   Neo4j 4.4.x **requires Java 11**. If your system defaults to a newer Java version (e.g., Java 17, 21), Neo4j might fail to start with errors like `Unrecognized VM option 'UseBiasedLocking'` or `Could not create the Java Virtual Machine`.
    *   **Solution:**
        1.  **Install OpenJDK 11:**
            ```bash
            sudo apt update && sudo apt install -y openjdk-11-jdk
            ```
        2.  **Set JAVA_HOME for the Neo4j Service:** Create a systemd override to explicitly tell the Neo4j service to use Java 11. The path to OpenJDK 11 is typically `/usr/lib/jvm/java-11-openjdk-arm64` (verify if different on your system).
            ```bash
            sudo mkdir -p /etc/systemd/system/neo4j.service.d
            echo -e '[Service]\nEnvironment="JAVA_HOME=/usr/lib/jvm/java-11-openjdk-arm64"' | sudo tee /etc/systemd/system/neo4j.service.d/override.conf
            sudo systemctl daemon-reload
            sudo systemctl restart neo4j
            ```
        3.  After these steps, verify with `sudo systemctl status neo4j --no-pager -l`. The service should be active and running, and the `Drop-In:` line should show your `override.conf`.

*   **Java Version:** The Neo4j 4.4.x series typically works well with Java 11 (OpenJDK 11 is recommended). If you encounter Java-related errors, ensure you have a compatible JDK installed and that Neo4j is configured to use it (check `/etc/neo4j/neo4j.conf` for `dbms.jvm.additional` settings if needed, though defaults usually work).
*   **Bolt Connector:** BloodHound connects to Neo4j via the Bolt protocol, typically at `bolt://localhost:7687`.
*   **Configuration:** Neo4j's main configuration file is `/etc/neo4j/neo4j.conf`.
*   **Data Location:** Data is typically stored in `/var/lib/neo4j/data/`.
*   **Logs:** Logs can be found in `/var/log/neo4j/`.

---

This setup provides a more robust and manageable Neo4j instance for your BloodHound analysis. 