use std::sync::LazyLock;

const BLOCK_PAGE: &str = r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blocked</title>
<style>
*{margin:0;box-sizing:border-box;border-radius:0}
body{min-height:100vh;display:grid;place-items:center;padding:24px;background:#020c03;color:#3dff5e;font:16px/1.5 Tahoma,Verdana,"DejaVu Sans",sans-serif}
main{width:100%;max-width:560px;padding:40px;border:3px solid #3dff5e}
h1{font-size:28px;letter-spacing:.24em;text-transform:uppercase}
p{margin-top:16px;color:#22a83c;word-break:break-all}
</style>
<main><h1>Blocked</h1><p id="url"></p></main>
<script>document.getElementById("url").textContent=location.href</script>
"#;

pub(crate) static BLOCK_RESPONSE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut out = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        BLOCK_PAGE.len()
    )
    .into_bytes();
    out.extend_from_slice(BLOCK_PAGE.as_bytes());
    out
});
