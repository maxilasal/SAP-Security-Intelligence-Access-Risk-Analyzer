# Extractor Z opcional (solo si se justifica)

**No es necesario para la versión 1.** Se propone únicamente cuando:

* la política de seguridad no acepta `S_TABU_NAM` sobre `USR02`/`UST12` para un usuario técnico;
* el volumen de `UST12`/`AGR_1251` hace inviable `RFC_READ_TABLE` (no liberado, sin cursor);
* se necesitan fuentes sin acceso tabular razonable (Security Audit Log, repositorio del launchpad).

## Diseño

* Módulo de función RFC `Z_SECX_READ`, grupo `ZSECX`, paquete propio, transportable, con revisión de código y ATC.
* **Solo lectura**: sin `INSERT/UPDATE/MODIFY/DELETE`, sin `COMMIT`, sin `CALL FUNCTION ... DESTINATION`, sin SQL dinámico sobre nombres de tabla recibidos.
* **Lista blanca en el servidor**: el llamador envía un identificador de dataset (`USERS`, `UST12`, …); tabla y campos están fijados en el código. Nunca se aceptan nombres de tabla/campo del cliente.
* **Campos de contraseña inexistentes** en las estructuras de salida.
* **Autorización propia** `Z_SECX` (campos `ZSECX_DS` = dataset, `ACTVT` = 03) además de `S_RFC`.
* **Paginación por clave** (`WHERE clave > última ORDER BY PRIMARY KEY UP TO n ROWS`), sin cursores entre llamadas.
* Límite de filas por llamada y registro en el application log (SLG1) de cada ejecución.

## Esqueleto (a revisar por desarrollo ABAP)

```abap
FUNCTION z_secx_read.
*"  IMPORTING  VALUE(iv_dataset)  TYPE char20
*"             VALUE(iv_after)    TYPE char72     " última clave devuelta
*"             VALUE(iv_max_rows) TYPE i DEFAULT 10000
*"  EXPORTING  VALUE(ev_last)     TYPE char72
*"             VALUE(ev_more)     TYPE abap_bool
*"  TABLES     et_ust12  STRUCTURE zsecx_s_ust12   " OBJCT AUTH FIELD VON BIS
*"             et_users  STRUCTURE zsecx_s_user    " BNAME USTYP CLASS GLTGV GLTGB UFLAG TRDAT
*"  EXCEPTIONS not_authorized invalid_dataset

  AUTHORITY-CHECK OBJECT 'Z_SECX' ID 'ZSECX_DS' FIELD iv_dataset ID 'ACTVT' FIELD '03'.
  IF sy-subrc <> 0. RAISE not_authorized. ENDIF.

  DATA(lv_max) = COND i( WHEN iv_max_rows BETWEEN 1 AND 50000 THEN iv_max_rows ELSE 10000 ).

  CASE iv_dataset.
    WHEN 'USERS'.
      SELECT bname, ustyp, class, gltgv, gltgb, uflag, trdat
        FROM usr02
        WHERE bname > @iv_after
        ORDER BY bname
        INTO CORRESPONDING FIELDS OF TABLE @et_users
        UP TO @lv_max ROWS.
      ev_more = xsdbool( lines( et_users ) = lv_max ).
      IF et_users[] IS NOT INITIAL. ev_last = et_users[ lines( et_users ) ]-bname. ENDIF.
    WHEN 'UST12'.
      " Paginación por OBJCT+AUTH concatenados en iv_after (diseño a detallar)
      ...
    WHEN OTHERS.
      RAISE invalid_dataset.
  ENDCASE.
ENDFUNCTION.
```

El backend Python ya incluye `Z_SECX_READ` en la lista permitida de funciones; el uso del
extractor se activaría por dataset en una fase posterior.
