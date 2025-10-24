/*
# Copyright 2022 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include "sigshared.h"

#include "./include/utility.h"
#include "./include/spright.h"

#define COPY_FIELD(dest, src) do {                             \
    if (src) {                                                 \
        strncpy(dest, src, sizeof(dest) - 1);                  \
        dest[sizeof(dest) - 1] = '\0';                         \
    } else {                                                   \
        dest[0] = '\0';                                        \
    }                                                          \
} while (0)




void set_node(uint8_t fn_id, uint8_t node_idx)
{
    sigshared_cfg->inter_node_rt[fn_id] = node_idx;
}

uint8_t get_node(uint8_t fn_id)
{
    uint8_t peer_node_idx = sigshared_cfg->inter_node_rt[fn_id];

    log_debug("Destination function is %u on node %u (%s:%u).", fn_id, peer_node_idx,
              sigshared_cfg->nodes[peer_node_idx].ip_address, INTERNAL_SERVER_PORT);

    return peer_node_idx;
}

void delete_node(uint8_t fn_id)
{
    sigshared_cfg->inter_node_rt[fn_id] = 0;
}

void print_ip_address(struct in_addr *ip)
{
    log_debug("%s", inet_ntoa(*ip));
}

void print_rt_table()
{
    printf("Inter-node Routing Table\n");
    for (int i = 1; i <= sigshared_cfg->n_nfs; i++)
    {
        printf("\tFn: %d, Node: %d\n", i, sigshared_cfg->inter_node_rt[i]);
    }
}

void PrintAdResponse(struct http_transaction *in)
{
    int i;
    log_debug("Ads in AdResponse:");
    for (i = 0; i < in->ad_response.num_ads; i++)
    {
        log_debug("Ad[%d] RedirectUrl: %s\tText: %s", i + 1, in->ad_response.Ads[i].RedirectUrl,
                 in->ad_response.Ads[i].Text);
    }
    printf("\n");
}

void PrintSupportedCurrencies(struct http_transaction *in)
{
    log_debug("Supported Currencies: ");
    int i = 0;
    for (i = 0; i < in->get_supported_currencies_response.num_currencies; i++)
    {
        log_debug("%d. %s\t", i + 1, in->get_supported_currencies_response.CurrencyCodes[i]);
    }
    printf("\n");
}

void PrintProduct(Product *p)
{
    log_debug("Product Name: %s\t ID: %s", p->Name, p->Id);
    log_debug("Product Description: %s", p->Description);
    log_debug("Product Picture: %s", p->Picture);
    log_debug("Product Price: %s %ld.%d", p->PriceUsd.CurrencyCode, p->PriceUsd.Units, p->PriceUsd.Nanos);
    log_debug("Product Categories: ");

    int i = 0;
    for (i = 0; i < p->num_categories; i++)
    {
        log_debug("%d. %s\t", i + 1, p->Categories[i]);
    }
    printf("\n");
}

void PrintListProductsResponse(struct http_transaction *txn)
{
    log_debug("### PrintListProductsResponse ###");
    ListProductsResponse *out = &txn->list_products_response;
    int size = sizeof(out->Products) / sizeof(out->Products[0]);
    int i = 0;
    for (i = 0; i < size; i++)
    {
        PrintProduct(&out->Products[i]);
    }
    return;
}

void PrintGetProductResponse(struct http_transaction *txn)
{
    log_debug("### PrintGetProductResponse ###");
    PrintProduct(&txn->get_product_response);
}

void PrintSearchProductsResponse(struct http_transaction *txn)
{
    log_debug("### PrintSearchProductsResponse ###");
    SearchProductsResponse *out = &txn->search_products_response;
    int i;
    for (i = 0; i < out->num_products; i++)
    {
        PrintProduct(&out->Results[i]);
    }
    return;
}

void PrintGetCartResponse(struct http_transaction *txn)
{
    log_debug("\t\t#### PrintGetCartResponse ####");
    Cart *out = &txn->get_cart_response;
    log_debug("Cart for user %s: ", out->UserId);

    if (txn->get_cart_response.num_items == -1)
    {
        log_debug("EMPTY CART!");
        return;
    }

    int i;
    for (i = 0; i < out->num_items; i++)
    {
        log_debug("\t%d. ProductId: %s \tQuantity: %d", i + 1, out->Items[i].ProductId, out->Items[i].Quantity);
    }
    printf("\n");
    return;
}

void PrintConversionResult(struct http_transaction *in)
{
    log_debug("Conversion result: ");
    log_debug("CurrencyCode: %s\t", in->currency_conversion_result.CurrencyCode);
    log_debug("Value: %ld.%d", in->currency_conversion_result.Units, in->currency_conversion_result.Nanos);
}

void printMoney(Money *money)
{
    printf("Money:\n");
    printf("  Currency Code: %s\n", money->CurrencyCode);
    printf("  Units: %ld\n", money->Units);
    printf("  Nanos: %d\n", money->Nanos);
}

void printCurrencyConversionRequest(CurrencyConversionRequest *request)
{
    printf("Currency Conversion Request:\n");
    printMoney(&request->From);
    printf("  To Currency Code: %s\n", request->ToCode);
}

void MockCurrencyConversionRequest(struct http_transaction *in)
{
    strcpy(in->currency_conversion_req.ToCode, "USD");
    strcpy(in->currency_conversion_req.From.CurrencyCode, "EUR");

    in->currency_conversion_req.From.Units = 300;
    in->currency_conversion_req.From.Nanos = 0;
}

void PrintProductView(struct http_transaction *txn)
{
    log_debug("\t\t#### ProductView ####");

    // int size = sizeof(txn->product_view)/sizeof(txn->product_view[0]);
    int size = txn->productViewCntr;
    int i = 0;
    for (i = 0; i < size; i++)
    {
        Product *p = &txn->product_view[i].Item;
        Money *m = &txn->product_view[i].Price;
        log_debug("Product Name: %s\t ID: %s", p->Name, p->Id);
        log_debug("Product %s Price:  %ld.%d", p->PriceUsd.CurrencyCode, p->PriceUsd.Units, p->PriceUsd.Nanos);
        log_debug("Product %s Price:  %ld.%d", m->CurrencyCode, m->Units, m->Nanos);
    }
}

void PrintListRecommendationsResponse(struct http_transaction *txn)
{
    log_debug("Recommended Product ID: %s", txn->list_recommendations_response.ProductId);
}

void PrintShipOrderResponse(struct http_transaction *txn)
{
    ShipOrderResponse *out = &txn->ship_order_response;
    log_debug("Tracking ID: %s", out->TrackingId);
}

void PrintGetQuoteResponse(struct http_transaction *txn)
{
    GetQuoteResponse *out = &txn->get_quote_response;
    log_debug("Shipping cost: %s %ld.%d", out->CostUsd.CurrencyCode, out->CostUsd.Units, out->CostUsd.Nanos);
}

void PrintTotalPrice(struct http_transaction *txn)
{
    log_debug("Total Price:  %ld.%d", txn->total_price.Units, txn->total_price.Nanos);
}

void Sum(Money *total, Money *add)
{

    total->Units = total->Units + add->Units;
    total->Nanos = total->Nanos + add->Nanos;

    if ((total->Units == 0 && total->Nanos == 0) || (total->Units > 0 && total->Nanos >= 0) ||
        (total->Units < 0 && total->Nanos <= 0))
    {
        // same sign <units, nanos>
        total->Units += (int64_t)(total->Nanos / NANOSMOD);
        total->Nanos = total->Nanos % NANOSMOD;
    }
    else
    {
        // different sign. nanos guaranteed to not to go over the limit
        if (total->Units > 0)
        {
            total->Units--;
            total->Nanos += NANOSMOD;
        }
        else
        {
            total->Units++;
            total->Nanos -= NANOSMOD;
        }
    }

    return;
}

void MultiplySlow(Money *total, uint32_t n)
{
    for (; n > 1;)
    {
        Sum(total, total);
        n--;
    }
    return;
}

void PrintPlaceOrderRequest(struct http_transaction *txn)
{
    log_debug("email: %s", txn->place_order_request.Email);
    log_debug("street_address: %s", txn->place_order_request.address.StreetAddress);
    log_debug("zip_code: %d", txn->place_order_request.address.ZipCode);
    log_debug("city: %s", txn->place_order_request.address.City);
    log_debug("state: %s", txn->place_order_request.address.State);
    log_debug("country: %s", txn->place_order_request.address.Country);
    log_debug("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);
    log_debug("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);
    log_debug("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);
    log_debug("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);


    
    log_info("email: %s", txn->place_order_request.Email);
    log_info("street_address: %s", txn->place_order_request.address.StreetAddress);
    log_info("zip_code: %d", txn->place_order_request.address.ZipCode);
    log_info("city: %s", txn->place_order_request.address.City);
    log_info("state: %s", txn->place_order_request.address.State);
    log_info("country: %s", txn->place_order_request.address.Country);
    log_info("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);
    log_info("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);
    log_info("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);
    log_info("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);


    log_info("ADDR: %ld", txn->addr);
}

//void parsePlaceOrderRequest(struct http_transaction *txn){
//
//    //PrintPlaceOrderRequest(txn);
//    //log_info("REQUEST: %s", txn->request);
//
//    //char query[HTTP_MSG_LENGTH_MAX];
//    //httpQueryParser(txn->request, query);
//    //if(query == NULL){
//    //	log_error("httpQueryParser retornou NULL");
//    //    exit(1);
//    //}
//
//
//    char aux[HTTP_MSG_LENGTH_MAX];
//    char *query = httpQueryParser(txn->request, aux);
//    if (query == NULL) {
//            log_error("httpQueryParser retornou NULL");
//            return;
//    }
// 
//
//    // log_debug("QUERY: %s", query);
//    //log_info("QUERY: %s", query);
//
//    char *start_of_query = strtok(query, "&");
//    // char *email = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.Email, strchr(start_of_query, '=') + 1);
//    // log_debug("email: %s", txn->place_order_request.Email);
//    //log_info("email: %s", txn->place_order_request.Email);
//
//    start_of_query = strtok(NULL, "&");
//    // char *street_address = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.address.StreetAddress, strchr(start_of_query, '=') + 1);
//    // log_debug("street_address: %s", txn->place_order_request.address.StreetAddress);
//    //log_info("street_address: %s", txn->place_order_request.address.StreetAddress);
//
//    start_of_query = strtok(NULL, "&");
//    // char *zip_code = strchr(start_of_query, '=') + 1;
//    txn->place_order_request.address.ZipCode = atoi(strchr(start_of_query, '=') + 1);
//    // log_debug("zip_code: %d", txn->place_order_request.address.ZipCode);
//    //log_info("zip_code: %d", txn->place_order_request.address.ZipCode);
//
//    start_of_query = strtok(NULL, "&");
//    // char *city = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.address.City, strchr(start_of_query, '=') + 1);
//    // log_debug("city: %s", txn->place_order_request.address.City);
//    //log_info("city: %s", txn->place_order_request.address.City);
//
//    start_of_query = strtok(NULL, "&");
//    // char *state = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.address.State, strchr(start_of_query, '=') + 1);
//    // log_debug("state: %s", txn->place_order_request.address.State);
//    //log_info("state: %s", txn->place_order_request.address.State);
//
//    start_of_query = strtok(NULL, "&");
//    // char *country = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.address.Country, strchr(start_of_query, '=') + 1);
//    // log_debug("country: %s", txn->place_order_request.address.Country);
//    //log_info("country: %s", txn->place_order_request.address.Country);
//
//    start_of_query = strtok(NULL, "&");
//    // char *credit_card_number = strchr(start_of_query, '=') + 1;
//    strcpy(txn->place_order_request.CreditCard.CreditCardNumber, strchr(start_of_query, '=') + 1);
//    // log_debug("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);
//    //log_info("credit_card_number: %s", txn->place_order_request.CreditCard.CreditCardNumber);
//
//    start_of_query = strtok(NULL, "&");
//    // char *credit_card_expiration_month = strchr(start_of_query, '=') + 1;
//    txn->place_order_request.CreditCard.CreditCardExpirationMonth = atoi(strchr(start_of_query, '=') + 1);
//    // log_debug("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);
//    //log_info("credit_card_expiration_month: %d", txn->place_order_request.CreditCard.CreditCardExpirationMonth);
//
//    start_of_query = strtok(NULL, "&");
//    // char *credit_card_expiration_year = strchr(start_of_query, '=') + 1;
//    txn->place_order_request.CreditCard.CreditCardExpirationYear = atoi(strchr(start_of_query, '=') + 1);
//    // log_debug("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);
//    //log_info("credit_card_expiration_year: %d", txn->place_order_request.CreditCard.CreditCardExpirationYear);
//
//    start_of_query = strtok(NULL, "&");
//    // char *credit_card_cvv = strchr(start_of_query, '=') + 1;
//    txn->place_order_request.CreditCard.CreditCardCvv = atoi(strchr(start_of_query, '=') + 1);
//    // log_debug("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);
//    //log_info("credit_card_cvv: %d", txn->place_order_request.CreditCard.CreditCardCvv);
//
//    free(query);    
//    //PrintPlaceOrderRequest(txn);
//}
/**********************************************************************/

void parsePlaceOrderRequest(struct http_transaction *txn){

    char aux[HTTP_MSG_LENGTH_MAX];
    //char *query = httpQueryParser(txn->request, aux);
    char *query = httpQueryParser(txn->request, aux, HTTP_MSG_LENGTH_MAX);
    if (!query){
	    log_error("httpQueryParser retornou NULL");
    	exit(1);
    } 

    char *param = strtok(query, "&");
    while (param) {
        char *key = strtok(param, "=");
        char *val = strtok(NULL, "=");
        if (!key || !val) continue;

        if (strcmp(key, "email") == 0)
            COPY_FIELD(txn->place_order_request.Email, val);
        else if (strcmp(key, "street") == 0)
            COPY_FIELD(txn->place_order_request.address.StreetAddress, val);
        else if (strcmp(key, "zip") == 0)
            txn->place_order_request.address.ZipCode = atoi(val);
        else if (strcmp(key, "city") == 0)
            COPY_FIELD(txn->place_order_request.address.City, val);
        else if (strcmp(key, "state") == 0)
            COPY_FIELD(txn->place_order_request.address.State, val);
        else if (strcmp(key, "country") == 0)
            COPY_FIELD(txn->place_order_request.address.Country, val);
        else if (strcmp(key, "ccnum") == 0)
            COPY_FIELD(txn->place_order_request.CreditCard.CreditCardNumber, val);
        else if (strcmp(key, "expmonth") == 0)
            txn->place_order_request.CreditCard.CreditCardExpirationMonth = atoi(val);
        else if (strcmp(key, "expyear") == 0)
            txn->place_order_request.CreditCard.CreditCardExpirationYear = atoi(val);
        else if (strcmp(key, "cvv") == 0)
            txn->place_order_request.CreditCard.CreditCardCvv = atoi(val);

        param = strtok(NULL, "&");
    }

    //free(query);
}




/*********************************************************************/
//char *httpQueryParser(char *req){
//char *httpQueryParser(char *req, char *query){
//
//    //char tmp[600];
//    char tmp[HTTP_MSG_LENGTH_MAX];
//    strcpy(tmp, req);
//    
//    //PrintPlaceOrderRequest(txn);
//    char *start_of_path = strtok(tmp, " ");
//    start_of_path = strtok(NULL, " ");
//
//    if(start_of_path == NULL){
//    	log_error("ERRO start_of_path == NULL");
//	exit(1);
//    }
//
//    //log_info("==start_of_path: %s", start_of_path);
//    char *start_of_query = strchr(start_of_path, '?') + 1;
//    query = strchr(start_of_path, '?') + 1;
//
//    if(start_of_query == NULL || query == NULL){
//	    log_error("start_of_query == NULL");
//	    exit(1);
//    }
//    
//    //log_info("--start_of_query: %s",  start_of_query);
//
//    // Remove trailing slash if present
//    size_t len       = strlen(start_of_query);
//    size_t len_query = strlen(query);
//    
//    if (start_of_query[len - 1] == '/'){
//        start_of_query[len - 1] = '\0';
//    }
//
//    if (query[len_query - 1] == '/'){
//        query[len_query - 1] = '\0';
//    }
//
//
//    //strncpy(query, start_of_query, sizeof(start_of_query));
//    //log_error("Tamanho do  len %d", len);
//    //return start_of_query;
//    return query;
//}

//char *auux;
//// TODO: garantir que sempre retorne certo e nao um NULL
//char *httpQueryParser(char *req, char *tmp){
//    if (req == NULL){
//	    log_error("txn->request passado eh NULL");
//	    exit(1);
//    } 
//
//    // Use a local copy for tokenizing
//    //char tmp[HTTP_MSG_LENGTH_MAX];
//    strncpy(tmp, req, sizeof(tmp) - 1);
//    tmp[sizeof(tmp) - 1] = '\0';
//	
//
//    char *method = strtok(tmp, " ");
//    char *path   = strtok(NULL, " ");
//    if (!path) return NULL;
//
//    char *qmark = strchr(path, '?');
//    if (!qmark) return NULL;
//
//    qmark++; // move past '?'
//
//    size_t len = strlen(qmark);
//    if (len > 0 && qmark[len - 1] == '/')
//        //qmark[len - 1] = '\0';
//        auux[len - 1] = '\0';
//    }
//
//    // Return a heap-allocated copy
//    //char *query = strdup(qmark);
//    //temp = strdup(qmark);
//    //return  strdup(qmark);
//
//    auux = strdup(qmark);
//    
//    log_info("auux: %s", auux);
//    
//    return  auux;
//
//    //if(!query){
//    //if(temp == NULL){
//    //        log_error("strdup returnou NULL(sem memoria)");
//    //        exit(1);
//    //}
//    //return query; // caller must free()
//    //return temp; // caller must free()
//}

char *httpQueryParser(const char *req, char *out, size_t outlen){

    if (!req || !out || outlen == 0)
        return NULL;

    char tmp[HTTP_MSG_LENGTH_MAX];
    strncpy(tmp, req, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *path = strtok(tmp, " ");
    path = strtok(NULL, " ");
    if (!path) return NULL;

    char *qmark = strchr(path, '?');
    if (!qmark) return NULL;

    qmark++;
    size_t len = strlen(qmark);
    if (len > 0 && qmark[len - 1] == '/')
        qmark[len - 1] = '\0';

    strncpy(out, qmark, outlen - 1);
    out[outlen - 1] = '\0';
    return out;
}



