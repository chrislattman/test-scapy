function testJson() {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/testjson", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            document.getElementById("answer").innerHTML = `<p>AJAX: ${xhr.responseText}</p>`;
        }
    };
    xhr.send(JSON.stringify({x: 5, y: 6}));
}
