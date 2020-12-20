#include <stdio.h>
#include <time.h>
#include <libakrypt.h>

bool_t ak_bckey_test_blowfish( void );

int main( void )
{
	/* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

	ak_bckey_test_blowfish();

	return ak_libakrypt_destroy();
}
