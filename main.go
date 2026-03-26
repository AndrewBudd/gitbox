package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gitboxcrypto "github.com/AndrewBudd/gitbox/internal/crypto"
	"github.com/AndrewBudd/gitbox/internal/hook"
	"github.com/AndrewBudd/gitbox/internal/store"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "add-user":
		err = cmdAddUser(args)
	case "add-key":
		err = cmdAddKey(args)
	case "refresh-keys":
		err = cmdRefreshKeys(args)
	case "group":
		err = cmdGroup(args)
	case "apply":
		err = cmdApply(args)
	case "export":
		err = cmdExport(args)
	case "encrypt":
		err = cmdEncrypt(args)
	case "decrypt":
		err = cmdDecrypt(args)
	case "grant":
		err = cmdGrant(args)
	case "revoke":
		err = cmdRevoke(args)
	case "list":
		err = cmdList(args)
	case "list-users":
		err = cmdListUsers(args)
	case "paper-key":
		err = cmdPaperKey(args)
	case "recover-identity":
		err = cmdRecoverIdentity(args)
	case "install-hook":
		err = cmdInstallHook(args)
	case "help", "--help", "-h":
		printUsage()
	case "version", "--version":
		fmt.Println("gitbox v0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`gitbox - Encrypt secrets in git using GitHub SSH keys as identity

Usage: gitbox <command> [arguments]

Identity Commands:
  add-user <username>          Fetch and store a GitHub user's SSH keys
  add-key <username> <key>     Add an SSH key manually (file path or inline)
  refresh-keys <user> [-k key] Re-fetch keys from GitHub and rebox all secrets
  list-users                   List all known identities

Group Commands:
  group create <name> <user1,user2,...>   Create a group
  group add <name> <user>                Add a user to a group
  group remove <name> <user>             Remove a user from a group
  group list                             List all groups
  group delete <name>                    Delete a group

Secret Commands:
  encrypt <file> -n <name> [-r <recipients>] [--no-self]
                               Encrypt (you are auto-included as recipient)
  decrypt <name> [-k <key>] [-o <file>]
                               Decrypt a secret
  grant <name> <user> [-k key] Grant access to a secret
  revoke <name> <user> [-k key] Revoke access (re-encrypts with new DEK)
  list                         List all secrets and their recipients

Config Commands:
  init                         Initialize .gitbox in the current repository
  apply [gitbox.yaml] [-k key] Apply declarative config (converge state)
  export                       Export current state as gitbox.yaml
  paper-key generate [-n name]  Generate emergency recovery paper key
  paper-key list                List all paper keys
  paper-key delete <name>       Remove a paper key
  paper-key recover <secret>    Decrypt using paper key
  recover-identity <user> <key.pub>
                               Recover identity + rebox secrets using paper key
  install-hook                 Install git pre-commit hook

Other:
  help                         Show this help message
  version                      Show version

Examples:
  gitbox init
  gitbox add-user octocat
  gitbox add-key contractor ~/.ssh/contractor_ed25519.pub
  gitbox group create backend alice,bob,charlie
  gitbox encrypt .env -n prod-secrets -r @backend,dave
  gitbox decrypt prod-secrets
  gitbox refresh-keys alice -k ~/.ssh/id_ed25519
  gitbox apply gitbox.yaml -k ~/.ssh/id_ed25519
  gitbox export > gitbox.yaml
`)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, ".gitbox")); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not in a git repository")
		}
		dir = parent
	}
}

func openStore() (*store.Store, string, error) {
	root, err := findRepoRoot()
	if err != nil {
		return nil, "", err
	}
	s, err := store.Open(root)
	if err != nil {
		return nil, "", err
	}
	return s, root, nil
}

// findSSHKeys tries to find usable SSH private keys in ~/.ssh
func findSSHKeys() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	sshDir := filepath.Join(home, ".ssh")
	candidates := []string{"id_ed25519", "id_rsa", "id_ecdsa"}
	var found []string
	for _, name := range candidates {
		path := filepath.Join(sshDir, name)
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}
	return found
}

// loadPrivateKey loads a private key from the specified path or searches ~/.ssh
func loadPrivateKey(keyPath string) (interface{}, error) {
	if keyPath != "" {
		return gitboxcrypto.LoadSSHPrivateKeyRaw(keyPath, nil)
	}

	keys := findSSHKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH keys found in ~/.ssh (specify with -k)")
	}

	var lastErr error
	for _, path := range keys {
		pk, err := gitboxcrypto.LoadSSHPrivateKeyRaw(path, nil)
		if err != nil {
			lastErr = err
			continue
		}
		return pk, nil
	}
	return nil, fmt.Errorf("could not load any SSH keys: %v", lastErr)
}

func cmdInit(args []string) error {
	root, err := findRepoRoot()
	if err != nil {
		// Use current directory if not in a git repo
		root, _ = os.Getwd()
	}

	s, err := store.Init(root)
	if err != nil {
		return err
	}
	host := s.GitHost()
	fmt.Printf("Initialized gitbox in %s\n", s.Root)
	if host != "github.com" {
		fmt.Printf("  Detected GitHub Enterprise: %s\n", host)
	}
	return nil
}

func cmdAddUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox add-user <github-username>")
	}
	username := args[0]

	s, _, err := openStore()
	if err != nil {
		return err
	}

	// Auto-discover signing key to vouch for the GitHub fetch
	signingKey, _ := loadPrivateKey("")

	fmt.Printf("Fetching SSH keys for %s from %s...\n", username, s.GitHost())
	id, err := s.AddUser(username, signingKey)
	if err != nil {
		return err
	}

	fmt.Printf("Added %s with %d key(s):\n", username, len(id.Keys))
	for _, k := range id.Keys {
		fmt.Printf("  %s %s\n", k.Type, k.Fingerprint)
	}
	return nil
}

func cmdEncrypt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox encrypt <file> -n <name> -r <user1,user2,...> [--no-self]")
	}

	var filePath, name, recipientStr, keyPath string
	noSelf := false
	filePath = args[0]

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "-r", "--recipients":
			if i+1 < len(args) {
				recipientStr = args[i+1]
				i++
			}
		case "-k", "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		case "--no-self":
			noSelf = true
		}
	}

	if name == "" {
		name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}

	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	s, root, err := openStore()
	if err != nil {
		return err
	}

	// Parse explicit recipients
	var recipients []string
	if recipientStr != "" {
		for _, r := range strings.Split(recipientStr, ",") {
			recipients = append(recipients, strings.TrimSpace(r))
		}
	}

	// Auto-include the operator unless --no-self
	if !noSelf {
		privKey, _ := loadPrivateKey(keyPath)
		if privKey != nil {
			if self, err := s.IdentifyKey(privKey); err == nil {
				found := false
				for _, r := range recipients {
					if r == self {
						found = true
						break
					}
				}
				if !found {
					recipients = append(recipients, self)
				}
			}
		}
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no recipients (specify with -r or ensure your SSH key matches a known identity)")
	}

	if err := s.EncryptSecret(name, plaintext, recipients); err != nil {
		return err
	}

	// Track the plaintext file for the pre-commit hook
	relPath, _ := filepath.Rel(root, filePath)
	if relPath == "" {
		relPath = filePath
	}
	_ = hook.TrackFile(root, relPath)
	_ = hook.EnsureGitignore(root, relPath)
	fmt.Printf("Encrypted %q as secret %q for %d recipient(s)\n", filePath, name, len(recipients))
	fmt.Printf("  Stored: .gitbox/secrets/%s.yaml\n", name)
	fmt.Printf("  Added %s to .gitignore\n", relPath)
	return nil
}

func cmdDecrypt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox decrypt <name> [-k <key-path>] [-o <output-file>]")
	}

	name := args[0]
	var keyPath, outputPath string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-k", "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	plaintext, err := s.DecryptSecret(name, privKey)
	if err != nil {
		return err
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Printf("Decrypted %q to %s\n", name, outputPath)
	} else {
		os.Stdout.Write(plaintext)
	}
	return nil
}

func cmdGrant(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gitbox grant <secret-name> <username> [-k <key-path>]")
	}

	secretName := args[0]
	username := args[1]
	var keyPath string
	for i := 2; i < len(args); i++ {
		if (args[i] == "-k" || args[i] == "--key") && i+1 < len(args) {
			keyPath = args[i+1]
			i++
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	if err := s.GrantAccess(secretName, username, privKey); err != nil {
		return err
	}

	fmt.Printf("Granted %s access to secret %q\n", username, secretName)
	return nil
}

func cmdRevoke(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gitbox revoke <secret-name> <username> [-k <key-path>]")
	}

	secretName := args[0]
	username := args[1]
	var keyPath string
	for i := 2; i < len(args); i++ {
		if (args[i] == "-k" || args[i] == "--key") && i+1 < len(args) {
			keyPath = args[i+1]
			i++
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	if err := s.RevokeAccess(secretName, username, privKey); err != nil {
		return err
	}

	fmt.Printf("Revoked %s access to secret %q (secret re-encrypted with new key)\n", username, secretName)
	return nil
}

func cmdList(args []string) error {
	s, _, err := openStore()
	if err != nil {
		return err
	}

	secrets, err := s.ListSecrets()
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets stored.")
		return nil
	}

	for _, name := range secrets {
		recipients, err := s.RecipientsForSecret(name)
		if err != nil {
			fmt.Printf("  %s (error reading recipients: %v)\n", name, err)
			continue
		}
		fmt.Printf("  %-30s recipients: %s\n", name, strings.Join(recipients, ", "))
	}
	return nil
}

func cmdListUsers(args []string) error {
	s, _, err := openStore()
	if err != nil {
		return err
	}

	users, err := s.ListUsers()
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Println("No users registered.")
		return nil
	}

	for _, u := range users {
		id, err := s.GetUser(u)
		if err != nil {
			fmt.Printf("  %s (error: %v)\n", u, err)
			continue
		}
		var keyTypes []string
		for _, k := range id.Keys {
			keyTypes = append(keyTypes, k.Type)
		}
		fmt.Printf("  %-25s keys: %s  (fetched: %s)\n", u, strings.Join(keyTypes, ", "), id.FetchedAt.Format("2006-01-02"))
	}
	return nil
}

func cmdPaperKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox paper-key <generate|recover|list|delete> ...")
	}

	switch args[0] {
	case "generate":
		return paperKeyGenerate(args[1:])
	case "recover":
		return paperKeyRecover(args[1:])
	case "list":
		return paperKeyList()
	case "delete":
		return paperKeyDelete(args[1:])
	default:
		return fmt.Errorf("unknown paper-key subcommand: %s", args[0])
	}
}

func paperKeyGenerate(args []string) error {
	var name, keyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "-k", "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	// Load signing key (required for signing the paper key config)
	signingKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("signing key required to create paper keys: %w", err)
	}

	pk, err := gitboxcrypto.GeneratePaperKey()
	if err != nil {
		return err
	}

	// Auto-generate name from fingerprint if not provided
	if name == "" {
		fp := pk.ToKeyInfo().Fingerprint
		// Use last 8 chars of fingerprint as a short name
		name = strings.TrimPrefix(fp, "SHA256:")
		if len(name) > 8 {
			name = name[:8]
		}
		name = strings.ToLower(name)
		// Make filesystem-safe
		name = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return '-'
		}, name)
	}

	if err := s.SavePaperKey(name, pk, signingKey); err != nil {
		return err
	}

	words := pk.Words()
	fingerprint := pk.ToKeyInfo().Fingerprint

	fmt.Println("Paper key generated successfully!")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", name)
	fmt.Printf("  Fingerprint: %s\n", fingerprint)
	fmt.Println()
	fmt.Println("WRITE THESE WORDS DOWN AND STORE THEM SECURELY:")
	fmt.Println("(This is the ONLY time they will be shown)")
	fmt.Println()
	fmt.Println("---BEGIN GITBOX PAPER KEY---")
	// Print words in numbered rows of 4
	wordList := strings.Fields(words)
	for i := 0; i < len(wordList); i += 4 {
		end := i + 4
		if end > len(wordList) {
			end = len(wordList)
		}
		parts := make([]string, end-i)
		for j := i; j < end; j++ {
			parts[j-i] = fmt.Sprintf("%2d. %-12s", j+1, wordList[j])
		}
		fmt.Println(strings.Join(parts, "  "))
	}
	fmt.Println("---END GITBOX PAPER KEY---")
	fmt.Println()
	fmt.Println("The paper key has been registered as a recovery recipient.")
	fmt.Println("New secrets will automatically be encrypted for all paper keys.")
	return nil
}

func paperKeyList() error {
	s, _, err := openStore()
	if err != nil {
		return err
	}

	keys, err := s.ListPaperKeys()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No paper keys registered.")
		return nil
	}

	for _, k := range keys {
		fmt.Printf("  %-20s owner: %-15s %s  (created: %s)\n", k.Name, k.Owner, k.Fingerprint, k.CreatedAt.Format("2006-01-02"))
	}
	return nil
}

func paperKeyDelete(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox paper-key delete <name>")
	}
	name := args[0]

	s, _, err := openStore()
	if err != nil {
		return err
	}

	if err := s.DeletePaperKey(name); err != nil {
		return fmt.Errorf("delete paper key %q: %w", name, err)
	}
	fmt.Printf("Deleted paper key %q\n", name)
	fmt.Println("Note: existing secrets still have this key as a recipient until re-encrypted.")
	return nil
}

func paperKeyRecover(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox paper-key recover <secret-name>\nYou will be prompted to enter your paper key hex.")
	}

	secretName := args[0]

	fmt.Print("Enter your 24 recovery words (or hex): ")
	var input string
	buf := make([]byte, 4096)
	n, err := os.Stdin.Read(buf)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	input = strings.TrimSpace(string(buf[:n]))

	// Try words first, fall back to hex
	pk, err := gitboxcrypto.PaperKeyFromWords(input)
	if err != nil {
		pk, err = gitboxcrypto.PaperKeyFromHex(input)
		if err != nil {
			return fmt.Errorf("invalid paper key (tried words and hex): %w", err)
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	plaintext, err := s.DecryptSecret(secretName, pk.PrivateKey)
	if err != nil {
		return fmt.Errorf("decrypt with paper key: %w", err)
	}

	os.Stdout.Write(plaintext)
	return nil
}

func cmdRecoverIdentity(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gitbox recover-identity <username> <new-pubkey-file>")
	}

	username := args[0]
	keyFile := args[1]

	pubKeyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read public key file: %w", err)
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	// Prompt for paper key words
	fmt.Print("Enter your 24 recovery words (or hex): ")
	buf := make([]byte, 4096)
	n, err := os.Stdin.Read(buf)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	input := strings.TrimSpace(string(buf[:n]))

	pk, err := gitboxcrypto.PaperKeyFromWords(input)
	if err != nil {
		pk, err = gitboxcrypto.PaperKeyFromHex(input)
		if err != nil {
			return fmt.Errorf("invalid paper key: %w", err)
		}
	}

	result, err := s.RecoverIdentity(username, string(pubKeyData), pk)
	if err != nil {
		return err
	}

	fmt.Printf("Identity %q updated with new keys, signed by paper key.\n", username)
	printReboxResult(username, result)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Commit the updated .gitbox/ directory")
	fmt.Println("  2. Consider generating a new paper key: gitbox paper-key generate -n <name>")
	return nil
}

func printReboxResult(username string, result *store.ReboxResult) {
	if result == nil {
		return
	}
	if result.Reboxed > 0 {
		fmt.Printf("  Reboxed %d secret(s) for %s's current keys.\n", result.Reboxed, username)
	}
	if len(result.Skipped) > 0 {
		fmt.Printf("  Warning: could not rebox %d secret(s) (no access to decrypt):\n", len(result.Skipped))
		for _, name := range result.Skipped {
			fmt.Printf("    - %s\n", name)
		}
		fmt.Println("  Another recipient with access to those secrets will need to run refresh-keys.")
	}
}

func cmdAddKey(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gitbox add-key <username> <key-file-or-pubkey-string> [-k <signing-key>]")
	}

	// Parse args: first positional is username, then key material, -k is signing key
	var username, keyPath string
	var pubKeyParts []string

	username = args[0]
	for i := 1; i < len(args); i++ {
		if (args[i] == "-k" || args[i] == "--key") && i+1 < len(args) {
			keyPath = args[i+1]
			i++
		} else {
			pubKeyParts = append(pubKeyParts, args[i])
		}
	}

	if len(pubKeyParts) == 0 {
		return fmt.Errorf("public key required")
	}

	keyArg := pubKeyParts[0]
	var pubKeyData string
	if _, err := os.Stat(keyArg); err == nil {
		data, err := os.ReadFile(keyArg)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		pubKeyData = string(data)
	} else {
		pubKeyData = strings.Join(pubKeyParts, " ")
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	// Load signing key for manual identities (optional during bootstrap)
	var signingKey interface{}
	if keyPath != "" {
		signingKey, err = loadPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("load signing key: %w", err)
		}
	} else {
		signingKey, _ = loadPrivateKey("") // best effort from ~/.ssh
	}

	if _, err := s.GetUser(username); err != nil {
		id, err := s.AddManualUser(username, pubKeyData, signingKey)
		if err != nil {
			return err
		}
		fmt.Printf("Created user %q with %d key(s):\n", username, len(id.Keys))
		for _, k := range id.Keys {
			fmt.Printf("  %s %s\n", k.Type, k.Fingerprint)
		}
	} else {
		added, result, err := s.AddKeyToUser(username, pubKeyData, signingKey)
		if err != nil {
			return err
		}
		fmt.Printf("Added %d key(s) to %q:\n", len(added), username)
		for _, k := range added {
			fmt.Printf("  %s %s\n", k.Type, k.Fingerprint)
		}
		printReboxResult(username, result)
	}
	return nil
}

func cmdRefreshKeys(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox refresh-keys <username|--all> [-k <key-path>]")
	}

	var keyPath string
	var targets []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k", "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		case "--all":
			targets = append(targets, "--all")
		default:
			targets = append(targets, args[i])
		}
	}

	s, _, err := openStore()
	if err != nil {
		return err
	}

	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return err
	}

	// Resolve --all
	if len(targets) == 1 && targets[0] == "--all" {
		users, err := s.ListUsers()
		if err != nil {
			return err
		}
		targets = users
	}

	for _, username := range targets {
		fmt.Printf("Refreshing keys for %s from %s...\n", username, s.GitHost())
		id, result, err := s.RefreshUserKeys(username, privKey)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}
		fmt.Printf("  Updated to %d key(s)\n", len(id.Keys))
		printReboxResult(username, result)
	}
	return nil
}

func cmdGroup(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gitbox group <create|add|remove|list|delete> ... [-k <signing-key>]")
	}

	// Extract -k flag from anywhere in args
	var keyPath string
	var filteredArgs []string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-k" || args[i] == "--key") && i+1 < len(args) {
			keyPath = args[i+1]
			i++
		} else {
			filteredArgs = append(filteredArgs, args[i])
		}
	}
	args = filteredArgs

	s, _, err := openStore()
	if err != nil {
		return err
	}

	// Load signing key for group mutations
	var signingKey interface{}
	if keyPath != "" {
		signingKey, err = loadPrivateKey(keyPath)
		if err != nil {
			return fmt.Errorf("load signing key: %w", err)
		}
	} else {
		signingKey, _ = loadPrivateKey("")
	}

	switch args[0] {
	case "create":
		if len(args) < 3 {
			return fmt.Errorf("usage: gitbox group create <name> <member1,member2,...>")
		}
		name := args[1]
		members := strings.Split(args[2], ",")
		for i := range members {
			members[i] = strings.TrimSpace(members[i])
		}

		groups, err := s.LoadGroups()
		if err != nil {
			return err
		}
		if _, exists := groups[name]; exists {
			return fmt.Errorf("group %q already exists", name)
		}
		groups[name] = members
		if err := s.SaveGroups(groups, signingKey); err != nil {
			return err
		}
		fmt.Printf("Created group %q with members: %s\n", name, strings.Join(members, ", "))

	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: gitbox group add <name> <user>")
		}
		name, user := args[1], args[2]
		groups, err := s.LoadGroups()
		if err != nil {
			return err
		}
		members, ok := groups[name]
		if !ok {
			return fmt.Errorf("group %q not found", name)
		}
		for _, m := range members {
			if m == user {
				return fmt.Errorf("%q already in group %q", user, name)
			}
		}
		groups[name] = append(members, user)
		if err := s.SaveGroups(groups, signingKey); err != nil {
			return err
		}
		fmt.Printf("Added %s to group %q\n", user, name)

	case "remove":
		if len(args) < 3 {
			return fmt.Errorf("usage: gitbox group remove <name> <user>")
		}
		name, user := args[1], args[2]
		groups, err := s.LoadGroups()
		if err != nil {
			return err
		}
		members, ok := groups[name]
		if !ok {
			return fmt.Errorf("group %q not found", name)
		}
		var updated []string
		found := false
		for _, m := range members {
			if m == user {
				found = true
			} else {
				updated = append(updated, m)
			}
		}
		if !found {
			return fmt.Errorf("%q not in group %q", user, name)
		}
		groups[name] = updated
		if err := s.SaveGroups(groups, signingKey); err != nil {
			return err
		}
		fmt.Printf("Removed %s from group %q\n", user, name)

	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("usage: gitbox group delete <name>")
		}
		name := args[1]
		groups, err := s.LoadGroups()
		if err != nil {
			return err
		}
		if _, ok := groups[name]; !ok {
			return fmt.Errorf("group %q not found", name)
		}
		delete(groups, name)
		if err := s.SaveGroups(groups, signingKey); err != nil {
			return err
		}
		fmt.Printf("Deleted group %q\n", name)

	case "list":
		groups, err := s.LoadGroups()
		if err != nil {
			return err
		}
		if len(groups) == 0 {
			fmt.Println("No groups defined.")
			return nil
		}
		for name, members := range groups {
			fmt.Printf("  @%-20s %s\n", name, strings.Join(members, ", "))
		}

	default:
		return fmt.Errorf("unknown group subcommand: %s", args[0])
	}
	return nil
}

func cmdApply(args []string) error {
	configPath := "gitbox.yaml"
	var keyPath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k", "--key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				configPath = args[i]
			}
		}
	}

	// Read config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config %s: %w", configPath, err)
	}

	var cfg store.GitBoxConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	s, root, err := openStore()
	if err != nil {
		return err
	}

	// Load private key (needed for grant/revoke on existing secrets)
	var privKey interface{}
	if keyPath != "" || len(findSSHKeys()) > 0 {
		privKey, _ = loadPrivateKey(keyPath)
	}

	// File reader resolves paths relative to repo root
	fileReader := func(path string) ([]byte, error) {
		fullPath := path
		if !filepath.IsAbs(path) {
			fullPath = filepath.Join(root, path)
		}
		return os.ReadFile(fullPath)
	}

	actions, err := s.Apply(&cfg, privKey, fileReader)
	if err != nil {
		return err
	}

	if len(actions) == 0 {
		fmt.Println("Already up to date.")
	} else {
		for _, a := range actions {
			fmt.Printf("  %s\n", a)
		}
		fmt.Printf("\n%d action(s) applied.\n", len(actions))
	}
	return nil
}

func cmdExport(args []string) error {
	s, _, err := openStore()
	if err != nil {
		return err
	}

	cfg, err := s.Export()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

func cmdInstallHook(args []string) error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	if err := hook.InstallHook(root); err != nil {
		return err
	}

	fmt.Println("Pre-commit hook installed.")
	fmt.Println("Plaintext secret files will be blocked from being committed.")
	return nil
}
