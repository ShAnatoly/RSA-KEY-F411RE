#ifndef INC_LOGGING_H_
#define INC_LOGGING_H_

#include "main.h"
#include "usart.h"

#ifdef __cplusplus
extern "C" {
#endif

HAL_StatusTypeDef usart_printf(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* INC_MPU6500_H_ */
