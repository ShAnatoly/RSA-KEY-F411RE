/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2024 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "dma.h"
#include "usart.h"
#include "usb_device.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "bignum.h"
#include "montgomery.h"
#include "rsa.h"
#include "logging.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef struct {
    uint8_t hours;
    uint8_t minutes;
    uint8_t seconds;
} packet_time_t;

typedef struct {
	uint16_t year;
	uint8_t month;
	uint8_t day;
} packet_date_t;

typedef struct {
    uint32_t plc_number;
    packet_time_t time;
    packet_date_t date;
} packet_t;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
const char pub_data[] =
        "-----BEGIN PUBLIC KEY-----"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOIkleXcUNZTiBRuAxYU6dCEKJLW6ZET"
        "FE81NUIVffzm+E75/mKGSkpgmb5KamsNo7SEgEAdKro0RkZZ0ia4Rc8CAwEAAQ=="
        "-----END PUBLIC KEY-----";

const char pvt_data[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA4iSV5dxQ1lOIFG4D"
        "FhTp0IQoktbpkRMUTzU1QhV9/Ob4Tvn+YoZKSmCZvkpqaw2jtISAQB0qujRGRlnS"
        "JrhFzwIDAQABAkEApRBHSYxShN5byW2zWv7Q255bbzLnMTlX7ajMwvulBl7ArgD+"
        "mjD30CzkN3C5m3MEuqC4Yz+/C3AgndnCRWrCIQIhAP8b2kDrrxXf9oloIKVHs85Q"
        "Trjxuh8VINHPWZIc+lWrAiEA4u7UEKH6G6RsDXHmoj6ekZwYOLJKSY6Em/h53BMB"
        "ZG0CIDtkpqmatYaoP+O5xG/2g5wzAkD4tlZqOtveJIJqELZFAiEAy029bN1ALW2D"
        "ZBQr1CSXeMnIJVsNFJL6mKTlv1TDhY0CIBFMJL5vaKTx5TSEEZPRB/NmbeV7joIq"
        "GLq7YHwu01m2"
        "-----END PRIVATE KEY-----";

rsa_pub_key_t pub_key;
rsa_pvt_key_t pvt_key;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
void usart_print_packet(packet_t packet) {
  usart_printf("%u) %02u.%02u.%02u %02u:%02u:%02u\r\n", packet.plc_number, packet.date.year, packet.date.month, packet.date.day, packet.time.hours, packet.time.minutes, packet.time.seconds);
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART2_UART_Init();
  MX_USB_DEVICE_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  // Парсинг ключей
  import_pub_key(&pub_key, pub_data);
  import_pvt_key(&pvt_key, pvt_data);

  // Инициализация пространств montgomery
  montg_t montg_domain;
  montg_init(&montg_domain, &pub_key.mod);

  // Инициализация переменных
  const char test_msg[BN_MSG_LEN + 1] = "";
  char out_enc[BN_BYTE_SIZE * 2 + 1] = "", out_dec[BN_MSG_LEN + 1] = "";
  char out_sign[BN_BYTE_SIZE * 2 + 1] = "", out_verify[BN_MSG_LEN + 1] = "";

  // Создание передаваемого пакета
  packet_t test_enc_packet;
  test_enc_packet.plc_number = 21;
  test_enc_packet.time.hours = 11;
  test_enc_packet.time.minutes = 22;
  test_enc_packet.time.seconds = 59;
  test_enc_packet.date.year = 2024;
  test_enc_packet.date.month = 3;
  test_enc_packet.date.day = 28;

  // Шифрование сообщения публичным ключом
  usart_printf("test packet: ");
  HAL_Delay(1000);
  usart_print_packet(test_enc_packet);
  memmove((char *) test_msg, &test_enc_packet, sizeof(packet_t));
  encrypt_buf(&pub_key, &montg_domain, test_msg, sizeof(test_msg), out_enc, sizeof(out_enc));

  // Дешифрование сообщения приватным ключом
  packet_t test_dec_packet;
  decrypt_buf(&pvt_key, &montg_domain, out_enc, strlen(out_enc), out_dec, sizeof(out_dec));
  memmove(&test_dec_packet, out_dec, sizeof(packet_t));
  usart_printf("decrypt packet: ");
  HAL_Delay(1000);
  usart_print_packet(test_dec_packet);
  HAL_Delay(1000);

  test_enc_packet = test_dec_packet;
  memset((char*)test_msg, ' ', sizeof(test_msg));

  // Шифрование сообщения приватным ключом / создание подписи
  usart_printf("sign packet: ");
  HAL_Delay(1000);
  usart_print_packet(test_enc_packet);
  memmove((char *) test_msg, &test_enc_packet, sizeof(packet_t));
  sign_buf(&pvt_key, &montg_domain, test_msg, sizeof(test_msg), out_sign, sizeof(out_sign));

  // Дешифрование сообщения публичным ключом / проверка подписи
  verify_buf(&pub_key, &montg_domain, out_sign, strlen(out_sign), out_verify, sizeof(out_verify));
  memmove(&test_dec_packet, out_verify, sizeof(packet_t));
  usart_printf("verify packet: ");
  HAL_Delay(1000);
  usart_print_packet(test_dec_packet);

  while (1) {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 96;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    Error_Handler();
  }
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
	/* User can add his own implementation to report the HAL error return state */
	__disable_irq();
	while (1) {
	}
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
