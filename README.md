# README.md (Русский)

# ---

### Основные функции
- **Шифрование файлов**: AES-256 для всех файлов на `C:\`.
- **Персистентность**: Автозагрузка, планировщик задач, отключение безопасного режима.
- **Блокировка**: Отключает Explorer, ввод, сеть, диспетчер задач.
- **Самораспространение**: Копируется на USB.
- **Удалённый ключ**: Отправляет ключ шифрования на сервер.
- **Повреждение**: Портит системные файлы и MBR при ошибке.
- **Откат**: Код `21122jam` восстанавливает систему.

### Зависимости
- Go 1.16+.
- Пакет golang.org/x/sys/windows:
 
  go get golang.org/x/sys/windows

НЕ ТЕСТИРОВАН
---
Main Features
File Encryption: AES-256 for all files on C:\.
Persistence: Autorun, scheduled tasks, safe mode disabled.
Lockdown: Disables Explorer, input, network, Task Manager.
Self-Spreading: Copies to USB drives.
Remote Key: Sends encryption key to a server.
Damage: Corrupts system files and MBR on error.
Rollback: Code 21122jam restores the system.
Dependencies
Go 1.16+.

Package golang.org/x/sys/windows:


go get golang.org/x/sys/windows

NOT TESTED
