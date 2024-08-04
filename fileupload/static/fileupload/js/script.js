document.addEventListener('DOMContentLoaded', () => {
    const resultCells = document.querySelectorAll('.result-cell');
    resultCells.forEach(cell => {
        const result = cell.textContent.trim().toLowerCase();
        if (result === 'none') {
            cell.classList.add('undetected');
            cell.innerHTML = '✅ Ninguno';
        } else {
            cell.classList.add('detected');
            cell.innerHTML = `☠️ ${cell.textContent.trim()}`;
        }
    });
});
