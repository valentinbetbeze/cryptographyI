#include "sha.h"
#include "utils.h"

#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FILE_BLOCK_SZ (1024) // Block size of a video file in byte.

int main(void)
{
    // ====================================================
    // Obtain the video file to work on
    // ====================================================

    printf("=== File downloading stage ===\n");

    // Create an empty file to store the downloaded content.
    const char *file_name = "video.mp4";
    FILE *file            = fopen(file_name, "wb");
    if (!file)
    {
        fprintf(stderr, "Failed to create %s\n", file_name);
        return 1;
    }

    // Download the video with cURL
    const char *url =
        "https://crypto.stanford.edu/~dabo/onlineCrypto/6.1.intro.mp4_download";

    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr, "curl_easy_init failed\n");
        fclose(file);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    CURLcode ret = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    // Make sure the file is written to disk.
    fclose(file);
    file = NULL;

    if (ret != CURLE_OK)
    {
        fprintf(stderr, "Curl failed with error %u\n", ret);
        return 1;
    }

    printf("=== File downloaded successfully ===\n\n");

    // ====================================================
    // Encode the file to get h0
    // ====================================================

    printf("=== File encoding stage ===\n");

    file = fopen(file_name, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open %s\n", file_name);
        return 1;
    }

    // Open a new file to store the video with the tagged blocks
    const char *file_tagged_name = "video_tagged.mp4";
    FILE *file_tagged            = fopen(file_tagged_name, "wb");
    if (!file_tagged)
    {
        fprintf(stderr, "Failed to create %s\n", file_name);
        fclose(file);
        return 1;
    }

    // Tag the video file
    uint8_t buf[FILE_BLOCK_SZ + SHA256_MD_SZ];
    uint8_t tag[SHA256_MD_SZ];

    memset(buf, 0, sizeof(buf));
    memset(tag, 0, sizeof(tag));

    // Move to the end of the file.
    fseek(file, 0, SEEK_END);

    // Compute the position of the last block
    long size      = ftell(file);
    long remainder = size % FILE_BLOCK_SZ;

    long blk_idx         = size / FILE_BLOCK_SZ - (remainder ? 0 : 1);
    long blk_size        = remainder ? remainder : FILE_BLOCK_SZ;
    long blk_tagged_size = blk_size;

    long file_pos        = blk_idx * FILE_BLOCK_SZ;
    long file_tagged_pos = blk_idx * sizeof(buf);

    while (file_pos >= 0)
    {
        // Get block
        fseek(file, file_pos, SEEK_SET);
        if (1 != fread(buf, blk_size, 1, file))
        {
            fprintf(stderr, "Failed to read file.\n");
            break;
        }

        // Append previous block's tag to the current block
        memcpy(buf + FILE_BLOCK_SZ, tag, sizeof(tag));

        // Write the tagged block into the new file
        fseek(file_tagged, file_tagged_pos, SEEK_SET);
        fwrite(buf, blk_tagged_size, 1, file_tagged);

        // Compute the hash of tagged block
        int ret = sha256(buf, blk_tagged_size, tag);
        if (ret)
        {
            fprintf(stderr, "SHA256 failed with error %u\n", ret);
            fclose(file);
            fclose(file_tagged);
            return 1;
        }

        // Update the state for the next block
        blk_size        = FILE_BLOCK_SZ;
        blk_tagged_size = sizeof(buf);

        file_pos -= blk_size;
        file_tagged_pos -= blk_tagged_size;
    }

    // Make sure the files are written to disk.
    fclose(file);
    fclose(file_tagged);
    file        = NULL;
    file_tagged = NULL;

    // The last tag is h0
    char h0[sizeof(tag) * 2 + 1] = {0};
    bytes_to_hex(tag, sizeof(tag), h0);
    h0[sizeof(h0) - 1] = '\0';
    printf("tag h0 = %s\n", h0);

    printf("=== File encoded successfully ===\n\n");

    // ====================================================
    // Verify each block of the file
    // ====================================================

    printf("=== File verification stage ===\n");

    file_tagged = fopen(file_tagged_name, "rb");
    if (!file_tagged)
    {
        fprintf(stderr, "Failed to create %s\n", file_name);
        return 1;
    }

    unsigned long n = 0;
    int blk_cnt     = 0;
    uint8_t prev_tag[SHA256_MD_SZ];
    memcpy(prev_tag, tag, sizeof(prev_tag));

    // Verify the integrity of each block
    while ((n = fread(buf, 1, sizeof(buf), file_tagged)) > 0)
    {
        // Compute the hash of the block
        int ret = sha256(buf, n, tag);
        if (ret)
        {
            fprintf(stderr, "SHA256 failed with error %u\n", ret);
            break;
        }

        // Compare the hash with the tag from the previous block
        if (0 != memcmp(prev_tag, tag, sizeof(prev_tag)))
        {
            fprintf(stderr,
                    "Error: file integrity check failed at block %i.\n",
                    blk_cnt);
            break;
        }

        // Keep the current block's tag
        memcpy(prev_tag, buf + FILE_BLOCK_SZ, sizeof(prev_tag));

        blk_cnt++;
    }

    // Stage outcome
    int err = ferror(file_tagged);
    if (err)
    {
        fprintf(stderr, "Reading tagged file failed with error %i.\n", err);
    }
    else if (feof(file_tagged))
    {
        printf("=== File verified successfully ===\n");
    }
    else
    {
        // Case-by-case error do not need extra handling
    }

    fclose(file_tagged);

    return 0;
}
