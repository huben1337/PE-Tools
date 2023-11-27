function Get-IconFromPng {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,
        [Parameter(Mandatory=$true)]
        [int32]$size,
        [bool]$png = $true
    )

    $image = [System.Drawing.Image]::FromFile((Get-Item $InputFile))
    $resizedImage = [System.Drawing.Bitmap]::new($size, $size)
    
    # change size using System.Drawing.Graphics
    $graphics = [System.Drawing.Graphics]::FromImage($resizedImage)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.DrawImage($image, 0, 0, $size, $size)

    $inputStream = [System.IO.MemoryStream]::new()
    $resizedImage.Save($inputStream, [System.Drawing.Imaging.ImageFormat]::Png)

    if ($png) {
        return $inputStream.ToArray()
    }

    $outputStream = [System.IO.MemoryStream]::new()
    $iconWriter = [System.IO.BinaryWriter]::new($outputStream)
    # 0-1 reserved, 0
    $iconWriter.Write([uint16]0);

    # 2-3 image type, 1 = icon, 2 = cursor
    $iconWriter.Write([uint16]1);

    # 4-5 number of images
    $iconWriter.Write([uint16]1);

    # image entry 1
    # 0 image width
    $iconWriter.Write([byte]($size % 256));
    # 1 image height
    $iconWriter.Write([byte]($size % 256));

    # 2 number of colors
    $iconWriter.Write([byte]0);

    # 3 reserved
    $iconWriter.Write([byte]0);

    # 4-5 color planes
    $iconWriter.Write([uint16]0);

    # 6-7 bits per pixel
    $iconWriter.Write([uint16]32);

    # 8-11 size of image data
    $iconWriter.Write([uint32]$inputStream.Length);

    # 12-15 offset of image data
    $iconWriter.Write([uint32](6 + 16));

    # write image data
    # png data must contain the whole png data file
    $iconWriter.Write($inputStream.ToArray());

    $iconWriter.Flush();

    return $outputStream.ToArray()
}

Export-ModuleMember -Function Get-IconFromPng