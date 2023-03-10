DropboxTransfer - консольная утилита для переноса файлов с/на Dropbox.
Для работы необходима учётная запись Dropbox.

### Установка

Для запуска необходим установленный интерпретатор **Python** версии 3.7 или выше (https://www.python.org/downloads/).
Прямая ссылка для загрузки под Windows 7 и выше: https://www.python.org/ftp/python/3.7.9/python-3.7.9-amd64.exe
Во время установки отметьте пункт "add Python to PATH". 
После установки обязательно перезагрузите систему.

Также для получения ключа доступа понадобится **веб-браузер**.
После установки интерпретатора Python необходимо перенести исполняемый файл программы (DropboxTransfer.py) и файл requirements.txt в папку откуда он 
будет запускаться.
Затем нужно запустить командную строку (команда cmd в Windows), перейти в ней в папку с программой и выполнить следующие команды:

`python -m pip install --upgrade pip`

`pip install -r requirements.txt`

### Запуск
Работа осуществляется из командной строки из папки, где находится запускающий файл программы командой:
`python DropboxTransfer.py`
Для корректной работы ПО необходимо указать следующие параметры по порядку:
1. Выбор направления загрузки: `up` для выгрузки **на** сервер Dropbox, `down` для загрузки **на** компьютер.
2. Исходный файл (включая путь к нему, относительный или абсолютный), например:  
   - в случае если мы **вы**гружаем (up): `file.rar`, или `c:\Documents\file.rar`
   - в случае если **за**гружаем (down): `/file.rar`, `"/some folder/file.rar"`
3. Конечный путь для файла (опционально), например:
   - если мы **вы**гружаем (up): `/`, `/folder`, `"/some folder/file.rar"`
   - если **за**гружаем (down): `file.rar`, `folder\file.jpeg`, `"c:\Documents and Settings\photo.jpeg"`

В случае если конечный путь не указан, то файл будет загружен по пути нахождения программы или выгружен в домашний каталог Dropbox.
Если в пути/названии файла есть пробелы, то необходимо заключать весь путь/название в кавычки: `""`.

Также необходимо понимать, что путь на сервере Dropbox начинается с символа `/`
Если не указывать имя файла при выгрузке, то название файла на сервере будет таким же как на компьютере.
При загрузке конечный каталог должен существовать.

Пример готовых строк для запуска может выглядеть следующим образом:

`python DropboxTransfer.py up file.rar "/some folder/"`

`python DropboxTransfer.py up "c:\Documents and Settings\photo.jpeg"`

`python DropboxTransfer.py down /folder/file.rar c:\documents\`

`python DropboxTransfer.py down "/some other folder/photo.jpeg"`

При первом запуске программе нужно будет получить ключ доступа.
Для этого будет сгенерирована ссылка, по которой нужно пройти и предоставить права доступа для приложения (ссылка откроется автоматически, либо в случае неуспеха будет предложено скопировать ссылку и пройти по ней самостоятельно).
После прохождения авторизации на сайте Dropbox и подтверждения прав для приложения, будет предложено скопировать код доступа в приложение.
Если код будет верным, то будет сгенерирован ключ доступа для приложения.
Эта операция нужна только один раз.
После этого начнётся процесс загрузки/выгрузки файла.

### Особенности
При выгрузке файлов в случае если путь и название файлов на сервере будут совпадать, то файл на сервере будет переименован.
Если при этом содержимое файлов будет совпадать, то новый файл создан не будет.
В общем случае коллизии отданы на откуп серверу Dropbox для самостоятельного решения.
При загрузке с Dropbox в случае совпадения имени локальный файл будет перезаписан.

ПО на данный момент не предназначено для выгрузки файлов размером более 150 Мб.

В случае если вам необходимо авторизоваться под другим пользователем, то вы можете удалить файл settings.ini находящийся в папке приложения, после чего процесс получения ключа доступа будет инициирован заново.


