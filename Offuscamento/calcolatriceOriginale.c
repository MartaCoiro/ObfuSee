#include <stdio.h>

int main() {
    char operatore;
    double num1, num2, risultato;

    printf("Inserisci un'operazione (+, -, *, /): ");
    scanf(" %c", &operatore);

    printf("Inserisci due numeri: ");
    scanf("%lf %lf", &num1, &num2);

    switch (operatore) {
        case '+':
            risultato = num1 + num2;
            printf("Risultato: %.2lf\n", risultato);
            break;
        case '-':
            risultato = num1 - num2;
            printf("Risultato: %.2lf\n", risultato);
            break;
        case '*':
            risultato = num1 * num2;
            printf("Risultato: %.2lf\n", risultato);
            break;
        case '/':
            if (num2 != 0) {
                risultato = num1 / num2;
                printf("Risultato: %.2lf\n", risultato);
            } else {
                printf("Errore: divisione per zero\n");
            }
            break;
        default:
            printf("Operatore non valido\n");
    }

    return 0;
}
