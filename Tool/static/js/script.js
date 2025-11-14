function simulateProgress() {
    const bar = document.getElementById('progress-bar');
    const timerSpan = document.getElementById('scan-timer');
    const cards = document.querySelectorAll('.test-card');
    if(!bar || !cards) return;

    let width = 0;
    let elapsed = 0;
    document.getElementById('progress').style.display = 'block';

    const interval = setInterval(() => {
        if(width >= 100) {
            clearInterval(interval);
            cards.forEach(card => card.classList.remove('opacity-0'));
        } else {
            width += 0.5;
            elapsed += 0.1;
            bar.style.width = width + '%';
            timerSpan.innerText = elapsed.toFixed(1);

            let index = Math.floor((width / 100) * cards.length);
            for(let i=0; i<=index && i<cards.length; i++){
                cards[i].classList.add('opacity-100');
                cards[i].classList.remove('opacity-0');
            }
        }
    }, 50);
}
