document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = document.getElementById('targetUrl').value;
    
    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        
        const data = await response.json();
        window.location.href = `/results/${data.scan_id}`;
    } catch (error) {
        alert('حدث خطأ أثناء بدء الفحص');
    }
});