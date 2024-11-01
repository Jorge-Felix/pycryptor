document.addEventListener('DOMContentLoaded', function() {
    const recipe = document.getElementById('recipe');
    const optionsPanel = document.getElementById('options-panel');
    const keyInput = document.querySelector('.key-input');
    const input = document.getElementById('input');
    const output = document.getElementById('output');

    // Función para actualizar el panel de opciones
    function updateOptionsPanel() {
        const operations = Array.from(recipe.children).map(op => op.dataset.op);
        
        // Verificar si hay operaciones que requieren clave
        const needsKey = operations.some(op => 
            ['aes_encrypt', 'aes_decrypt', 'des_encrypt', 'des_decrypt',
             'vigenere_encrypt', 'vigenere_decrypt'].includes(op)
        );

        if (needsKey) {
            optionsPanel.classList.remove('hidden');
            keyInput.classList.remove('hidden');
        } else {
            optionsPanel.classList.add('hidden');
            keyInput.classList.add('hidden');
        }
    }

    // Configurar drag and drop
    recipe.addEventListener('dragover', (e) => {
        e.preventDefault();
        recipe.classList.add('drag-over');
    });

    recipe.addEventListener('dragleave', () => {
        recipe.classList.remove('drag-over');
    });

    recipe.addEventListener('drop', (e) => {
        e.preventDefault();
        recipe.classList.remove('drag-over');
        
        const operationType = e.dataTransfer.getData('text/plain');
        console.log('Operación arrastrada:', operationType);
        
        const opElement = document.createElement('div');
        opElement.className = 'recipe-operation';
        opElement.dataset.op = operationType;
        opElement.innerHTML = `
            <span>${operationType.replace(/_/g, ' ').toUpperCase()}</span>
            <button class="remove-btn">×</button>
        `;

        recipe.appendChild(opElement);

        opElement.querySelector('.remove-btn').addEventListener('click', () => {
            opElement.remove();
            updateOptionsPanel();
        });

        updateOptionsPanel();
    });

    // Hacer las operaciones arrastrables
    document.querySelectorAll('.operation').forEach(op => {
        op.draggable = true;
        op.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', op.dataset.op);
        });
    });

    // Botón para procesar (bake)
    document.getElementById('bake').addEventListener('click', async () => {
        try {
            const operations = Array.from(recipe.children).map(op => {
                const operation = {
                    type: op.dataset.op
                };
                
                // Agregar clave si la operación la requiere
                if (['aes_encrypt', 'aes_decrypt', 'des_encrypt', 'des_decrypt',
                     'vigenere_encrypt', 'vigenere_decrypt'].includes(op.dataset.op)) {
                    const key = document.getElementById('crypto-key').value;
                    if (!key) {
                        throw new Error('Se requiere una clave para el cifrado');
                    }
                    operation.key = key;
                }
                
                return operation;
            });

            console.log('Enviando operaciones:', operations); // Para debug

            const response = await fetch('/process', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    input: input.value,
                    operations: operations
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `Error HTTP: ${response.status}`);
            }

            const result = await response.json();
            
            if (result.error) {
                output.value = `Error: ${result.error}`;
            } else {
                output.value = result.output;
            }
        } catch (error) {
            console.error('Error:', error);
            output.value = `Error: ${error.message}`;
        }
    });

    // Botón para copiar
    document.getElementById('copy-output')?.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(output.value);
            const copyButton = document.getElementById('copy-output');
            copyButton.textContent = '¡Copiado!';
            setTimeout(() => {
                copyButton.textContent = 'Copiar';
            }, 2000);
        } catch (err) {
            console.error('Error al copiar:', err);
            alert('No se pudo copiar el texto');
        }
    });

    // Toggle para mostrar/ocultar la clave
    document.getElementById('toggle-key-visibility')?.addEventListener('click', () => {
        const cryptoKey = document.getElementById('crypto-key');
        const toggleButton = document.getElementById('toggle-key-visibility');
        if (cryptoKey.type === 'password') {
            cryptoKey.type = 'text';
            toggleButton.innerHTML = '<i>👁️</i> Ocultar clave';
        } else {
            cryptoKey.type = 'password';
            toggleButton.innerHTML = '<i>👁️</i> Mostrar clave';
        }
    });
});