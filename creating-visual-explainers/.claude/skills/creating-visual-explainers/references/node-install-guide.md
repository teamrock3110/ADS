# Node.js インストールガイド

SKILL.md の Step 5 で Node.js が未インストールだった場合に参照する。

## 説明と許可

以下をユーザーに伝え、インストールの許可を求める:

> 図解の作成は完了しました。`output/` フォルダ内の HTML ファイルをブラウザにドラッグ＆ドロップすれば、今すぐ確認できます。
>
> URLで公開するには「Node.js」のインストールが必要です。
> Node.js は、パソコン上でプログラムを動かすための土台で、世界中で使われている安全な道具です。
> **README にも記載の通り、AI-Driven School 運営が確認済みですので安心してください。**
>
> 今からインストールしてもよいですか？

ユーザーが許可しなかった場合 → ファイルの確認方法（生成された HTML ファイルをブラウザで開く）を伝えて終了。

## macOS の場合

インストーラーをダウンロードする:

```bash
PKG_NAME=$(curl -sL https://nodejs.org/dist/latest-lts/ | grep -o 'node-v[0-9.]*\.pkg' | head -1) && curl -fsSL "https://nodejs.org/dist/latest-lts/${PKG_NAME}" -o /tmp/node-install.pkg && echo "ダウンロード完了: ${PKG_NAME}"
```

ダウンロード完了後、インストールを実行する**前に**以下を伝える:

> インストールのために、パソコンのパスワードの入力が必要です。
> これはパソコンにログインするときに使っているパスワードです。
> 画面下のターミナル欄にパスワードを入力して Enter を押してください。
> 入力中の文字は画面に表示されませんが、正常な動作です。

```bash
sudo installer -pkg /tmp/node-install.pkg -target / && rm /tmp/node-install.pkg
```

## Windows の場合

インストールを実行する**前に**以下を伝える:

> インストール中に「このアプリがデバイスに変更を加えることを許可しますか？」という確認画面が表示されることがあります。
> 「はい」を押してください。

```powershell
winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
```

インストール完了後、現在のターミナルで Node.js を使えるようにする:

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

winget が使えない場合（「winget は認識されていません」と表示された場合）:

```powershell
$msi = (Invoke-WebRequest -Uri "https://nodejs.org/dist/latest-lts/" -UseBasicParsing).Links.href | Where-Object { $_ -match "x64\.msi$" } | Select-Object -First 1; Invoke-WebRequest -Uri "https://nodejs.org/dist/latest-lts/$msi" -OutFile "$env:TEMP\node-install.msi" -UseBasicParsing; Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\node-install.msi`"" -Verb RunAs -Wait; Remove-Item "$env:TEMP\node-install.msi"
```

## インストール完了の確認

```bash
node --version
```

バージョン番号が表示された → インストール成功。
エラーが出た → Cursor を再起動してからもう一度試すよう案内する。
