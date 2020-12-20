
 #include <ak_tools.h>
 #include <ak_bckey.h>
 #include <ak_hash.h>
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_STDIO_H
 #include <stdio.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */


#define N 16

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Таблицы, используемые для реализации алгоритма. */
 static ak_uint32 ak_blowfish_matrix[4][256];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Развернутые раундовые ключи и маски алгоритма Blowfish.
    \details Массив содержит в себе записанные последовательно следующие ключи и маски
    (последовательно, по 18 ключей из 32-х битных слов на каждый ключ)
      - раундовые ключи для алгоритма зашифрования
      - раундовые ключи для алгоритма расшифрования
      - маски для раундовых ключей алгоритма зашифрования
      - маски для раундовых ключей алгоритма расшифрования. */
typedef ak_uint32 ak_blowfish_expanded_keys[(N + 2)*4];

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_init_blowfish_tables( void )
{
  int i, j;
  for( i = 0; i < 4; i++ )
  {
      for( j = 0; j < 256; j++ )
      {
         ak_blowfish_matrix[i][j] = SBOX[i][j];
      }
  }

  if( ak_log_get_level() >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "initialization is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Blowfish.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_blowfish_delete_keys( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( skey->data != NULL ) {
   /* теперь очистка и освобождение памяти */
    if(( error = ak_ptr_context_wipe( skey->data, sizeof( ak_blowfish_expanded_keys ),
                                                  &skey->generator)) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect wiping an internal data" );
      memset( skey->data, 0, sizeof( ak_blowfish_expanded_keys ));
    }
    free( skey->data );
    skey->data = NULL;
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует инициализацию таблиц замены с помощью операций сложения               */
/*  по модулю 2 и по модулю 2^32.                                                                  */
/* ----------------------------------------------------------------------------------------------- */
static ak_uint32 ak_blowfish_F( ak_uint32 x )
{
   ak_uint32 a, b, c, d;
   ak_uint32  y;

   d = (ak_uint32)(x & 0xFF);
   x >>= 8;
   c = (ak_uint32)(x & 0xFF);
   x >>= 8;
   b = (ak_uint32)(x & 0xFF);
   x >>= 8;
   a = (ak_uint32)(x & 0xFF);
   y = ak_blowfish_matrix[0][a] + ak_blowfish_matrix[1][b];
   y ^= ak_blowfish_matrix[2][c];
   y += ak_blowfish_matrix[3][d];

   return y;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Blowfish.                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_blowfish_encrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint32 *ekey = ( ak_uint32 *)skey->data;
  ak_uint32 *mekey = ( ak_uint32 *)skey->data + 36;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint32 x[2];
  ak_uint32 t;

  x[0] = (( ak_uint32 *) in)[0];
  x[1] = (( ak_uint32 *) in)[1];

  for ( i = 0; i < N; ++i )
  {
    x[0] ^= ekey[i];
    x[0] ^= mekey[i];
    x[1] ^= ak_blowfish_F( x[0] );

    t = x[0];
    x[0] = x[1];
    x[1] = t;
  }

  t = x[0];
  x[0] = x[1];
  x[1] = t;

  x[0] ^= ekey[17];
  x[0] ^= mekey[17]; 
  x[1] ^= ekey[16];
  x[1] ^= mekey[16];

  ((ak_uint32 *)out)[0] = x[0];
  ((ak_uint32 *)out)[1] = x[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Blowfish.                                                                               */
/* ----------------------------------------------------------------------------------------------- */
static void ak_blowfish_decrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_uint32 *dkey = ( ak_uint32 *)skey->data + 18;
  ak_uint32 *mdkey = ( ak_uint32 *)skey->data + 54;

 /* чистая реализация для 64х битной архитектуры */
  ak_uint32 x[2];
  ak_uint32 t;

  x[0] = (( ak_uint32 *) in)[0];
  x[1] = (( ak_uint32 *) in)[1];

  for (i = N + 1; i > 1; --i)
  {
    x[0] ^= dkey[i];
    x[0] ^= mdkey[i];
    x[1] ^= ak_blowfish_F( x[0] );

    t = x[0];
    x[0] = x[1];
    x[1] = t;
  }

  t = x[0];
  x[0] = x[1];
  x[1] = t;

  x[0] ^= dkey[0]; 
  x[0] ^= mdkey[0];
  x[1] ^= dkey[1];
  x[1] ^= mdkey[1];

  ((ak_uint32 *)out)[0] = x[0];
  ((ak_uint32 *)out)[1] = x[1];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Blowfish.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_blowfish_schedule_keys( ak_skey skey )
{ ak_uint8 reverse[32];
  int i = 0, j = 0, k = 0;
  ak_uint32 buf, data[2];
  ak_uint32 *ekey = NULL, *dkey = NULL, *mekey = NULL, *mdkey = NULL,*rkey = NULL, *lkey = NULL;
   ak_int32 oc = ak_libakrypt_get_option( "openssl_compability" );
 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* удаляем былое */
  if( skey->data != NULL ) ak_blowfish_delete_keys( skey );

 /* далее, по-возможности, выделяем выравненную память */
  if(( skey->data = ak_libakrypt_aligned_malloc( sizeof( ak_blowfish_expanded_keys ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = ( ak_uint32 *)skey->data;                  /* 18 прямых раундовых ключей */
  dkey = ( ak_uint32 *)skey->data + 18;           /* 18 обратных раундовых ключей */
  mekey = ( ak_uint32 *)skey->data + 36;   /* 18 масок для прямых раундовых ключей */
  mdkey = ( ak_uint32 *)skey->data + 54; /* 18 масок для обратных раундовых ключей */
  if( oc ) { /* разворачиваем ключ в каноническое представление */
    for( i = 0; i < 16; i++ ) {
       reverse[i] = skey->key[15-i];
       reverse[16+i] = skey->key[33-i];
    }
    lkey = ( ak_uint32 *)reverse;
    rkey = ( ak_uint32 *)( reverse + skey->key_size );
  } else {
    lkey = ( ak_uint32 *)skey->key; /* исходный ключ */
    rkey = ( ak_uint32 *)( skey->key + skey->key_size );
  }
  
    
  /* за один вызов вырабатываем маски для прямых и обратных ключей */
  skey->generator.random( &skey->generator, mekey, 36*sizeof( ak_uint32 ));

  skey->unmask ( skey );

 /* только теперь выполняем алгоритм развертки ключа */ 
  for ( i = 0; i < N + 2; ++i )
  {
    buf = 0x00000000;
    for ( k = 0; k < 4; ++k )
    {
      buf = ( buf << 8 ) | (( ak_uint8 *)lkey)[j];
      j = j + 1;
      if ( j >= 8 )
        j = 0;
    }
    ekey[i] = P[i] ^ buf;
    dkey[i] = ekey[i];
    ekey[i] ^= mekey[i];
    dkey[i] ^= mdkey[i];
  }

  data[0] = 0x00000000;
  data[1] = 0x00000000;

  for ( i = 0; i < N + 2; i += 2 )
  {
    ak_blowfish_encrypt( skey, &data, &data );
    ekey[i] = data[0];
    ekey[i + 1] = data[1];
    dkey[i] = ekey[i];
    dkey[i + 1] = ekey[i + 1];
    ekey[i] ^= mekey[i];
    ekey[i + 1] ^= mekey[i + 1];
    dkey[i] ^= mdkey[i];
    dkey[i + 1] ^= mdkey[i + 1];
  }

  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 256; j += 2)
    {
      ak_blowfish_encrypt( skey, &data, &data );
      ak_blowfish_matrix[i][j] = data[0];
      ak_blowfish_matrix[i][j + 1] = data[1];
    }
  }

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_context_create_blowfish( ak_bckey bkey )
{
     int error = ak_error_ok;
     if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to block cipher key context" );

    /* создаем ключ алгоритма шифрования и определяем его методы */
     if(( error = ak_bckey_context_create( bkey, 8, 8 )) != ak_error_ok )
       return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

 

    /* устанавливаем методы */
     bkey->schedule_keys = ak_blowfish_schedule_keys;
     bkey->delete_keys = ak_blowfish_delete_keys;
     bkey->encrypt = ak_blowfish_encrypt;
     bkey->decrypt = ak_blowfish_decrypt;

     return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование алгоритма Blowfish.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_test_blowfish( void )
{
  char *str = NULL;
  struct bckey bkey;
  bool_t result = ak_true;
  int error = ak_error_ok;

  /* тестовый ключ 0x4fb05e1515ab73a7 (источник: https://www.schneier.com/code/vectors.txt) */
  ak_uint8 testkey[8] = {
            0x4f, 0xb0, 0x5e, 0x15, 0x15, 0xab, 0x73, 0xa7
    };

 /* открытый текст 0x072d43a077075292 (источник: https://www.schneier.com/code/vectors.txt) */
  ak_uint32 plain_text[2] = { 0x072d43a0, 0x77075292 };

 /* зашифрованный текст 0x7a8e7bfa937e89a3 (источник: https://www.schneier.com/code/vectors.txt) */
  ak_uint32 cipher_text[2] = { 0x7a8e7bfa, 0x937e89a3 };

 /* временный буффер */
  ak_uint32 buf[2];

 /* 1. Создаем контекст ключа алгоритма Blowfish и устанавливаем значение ключа */
  if(( error = ak_bckey_context_create_blowfish( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of blowfish secret key context");
    return ak_false;
  }

  if(( error = ak_bckey_context_set_key( &bkey, testkey, sizeof( testkey ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of test key" );
    result = ak_false;
    goto exit;
  }

 /* 2. Тестируем зашифрование/расшифрование одного блока */
  printf ("\nKey:\t\t\t");
  for (int i = 0; i < 8; ++i)
    printf ("%02x", testkey[i]);

  printf ("\nPlain text:\t\t");
  for (int i = 0; i < 2; ++i)
    printf ("%08x ", plain_text[i]);

  printf ("\nSipher text:\t\t");
  for (int i = 0; i < 2; ++i)
    printf ("%08x ", cipher_text[i]);
  printf ("\n");


  bkey.encrypt( &bkey.key, plain_text, buf );

  printf ("\nEncrypted plain text:\t");
  for (int i = 0; i < 2; ++i)
    printf ("%08x ", buf[i]);

   if( !ak_ptr_is_equal( buf, cipher_text, 2 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block encryption test is wrong");
     
     result = ak_false;
     goto exit;
   }
   else
   printf ("\nEncryption is ok.\n");

  bkey.decrypt( &bkey.key, cipher_text, buf );

  printf ("\nDecrypted cipher text:\t");
  for (int i = 0; i < 2; ++i)
    printf ("%08x ", buf[i]);

  if( !ak_ptr_is_equal( buf, plain_text, 2 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                       "the one block decryption test wrong");
  
    result = ak_false;
    goto exit;
    }
   else 
  printf ("\nDecryption is ok.\n\n");

 /* освобождаем ключ и выходим */
  exit:
  if(( error = ak_bckey_context_destroy( &bkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong destroying of secret key" );
    return ak_false;
  }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_blowfish.c  */
/* ----------------------------------------------------------------------------------------------- */

