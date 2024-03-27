#include "logging.h"
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define USART_TxBufSize 255
static char USART_TxBuffer[USART_TxBufSize];

HAL_StatusTypeDef usart_printf(const char *format, ...) {
    va_list args;
    uint32_t length = 0;

    va_start(args, format);

    length = vsnprintf((char *)USART_TxBuffer, USART_TxBufSize, (char *)format, args);
    va_end(args);
    return HAL_UART_Transmit_DMA(&huart2, USART_TxBuffer, length);
}
